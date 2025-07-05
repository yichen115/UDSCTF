#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include "iso14229.h"
#include <time.h>
#include <sys/select.h>
#include <signal.h>

#define PUBLIC_FLAG "UDSCTF{VINYICHEN00112233}"
#define SECURE_FLAG "UDSCTF{27_securityX0r_C1C2}"
#define ADVANCED_FLAG "UDSCTF{D1D2_Advanced_Flag}"
#define BOOT_FLAG "UDSCTF{Reset_ThE_UDS_Server}"
#define MEMORY_FLAG "UDSCTF{ReadMemory_T0_Find_Flag}"
#define UDS_PHYS_ID 0x7E0
#define UDS_RESP_ID 0x7E8

// 全局ELF文件数据缓冲区
static uint8_t *g_elf_data = NULL;
static size_t g_elf_size = 0;

static uint32_t g_seed = 0;
static int security_unlocked = 0;
static uint8_t current_session = 0x01; // 默认会话
static uint8_t security_level = 0; // 当前安全访问级别
static time_t last_tester_present_time = 0; // 记录上次TesterPresent时间

// 信号处理函数
void segfault_handler(int sig) {
    printf("[LOG] 捕获到段错误信号 %d，程序安全退出\n", sig);
    exit(1);
}

uint32_t generate_seed() {
    return (uint32_t)rand();
}

uint32_t calc_key(uint32_t seed) {
    return seed ^ 0xdeadbeef;
}

uint32_t calc_key_level3(uint32_t seed) {
    // 更复杂的级别3密钥算法
    uint32_t key = seed;
    
    // 步骤1: 循环左移
    key = (key << 7) | (key >> 25);
    
    // 步骤2: 异或操作
    key ^= 0xCAFEBABE;
    
    // 步骤3: 加法运算
    key += 0x12345678;
    
    // 步骤4: 位运算
    key = (key & 0xFFFF0000) | ((key & 0x0000FFFF) ^ 0xABCD);
    
    // 步骤5: 最终异或
    key ^= 0xDEADBEEF;
    
    return key;
}

uint32_t calc_key_level5(uint32_t seed) {
    // 级别5密钥算法 - 更复杂
    uint32_t key = seed;
    
    // 步骤1: 多重异或
    key ^= 0x12345678;
    key ^= 0x87654321;
    
    // 步骤2: 循环右移
    key = (key >> 13) | (key << 19);
    
    // 步骤3: 位运算
    key = (key & 0xFF00FF00) | ((key & 0x00FF00FF) ^ 0x55555555);
    
    // 步骤4: 加法运算
    key += 0xDEADBEEF;
    
    // 步骤5: 最终异或
    key ^= 0xCAFEBABE;
    
    return key;
}

// 发送启动flag
void send_boot_flag(int s) {
    printf("[LOG] 发送启动flag: %s\n", BOOT_FLAG);
    
    // 直接发送启动flag，不等待流控帧
    struct can_frame txf;
    txf.can_id = UDS_RESP_ID;
    
    // 构造UDS响应格式：0x62 + DID + flag数据
    uint8_t uds_header[3];
    uds_header[0] = 0x62; // ReadDataByIdentifier响应
    uds_header[1] = 0x00; // 虚拟DID高字节
    uds_header[2] = 0x00; // 虚拟DID低字节
    
    size_t total_len = 3 + strlen(BOOT_FLAG);
    
    if (total_len <= 7) {
        // 单帧发送
        txf.data[0] = total_len; // ISO-TP长度字段
        memcpy(&txf.data[1], uds_header, 3);
        memcpy(&txf.data[4], BOOT_FLAG, strlen(BOOT_FLAG));
        txf.can_dlc = 1 + total_len;
    } else {
        // 多帧发送（简化版，不等待FC帧）
        // 首帧
        txf.data[0] = 0x10 | ((total_len >> 8) & 0x0F);
        txf.data[1] = total_len & 0xFF;
        memcpy(&txf.data[2], uds_header, 3);
        memcpy(&txf.data[5], BOOT_FLAG, 3); // 只复制前3字节
        txf.can_dlc = 8;
        write(s, &txf, sizeof(struct can_frame));
        
        // 连续帧发送剩余数据
        size_t sent = 3;
        uint8_t sn = 1;
        while (sent < strlen(BOOT_FLAG)) {
            txf.data[0] = 0x20 | (sn & 0x0F);
            size_t remain = strlen(BOOT_FLAG) - sent;
            size_t chunk = remain > 7 ? 7 : remain;
            memcpy(&txf.data[1], BOOT_FLAG + sent, chunk);
            txf.can_dlc = 1 + chunk;
            write(s, &txf, sizeof(struct can_frame));
            sent += chunk;
            sn = (sn + 1) & 0x0F;
            usleep(1000 * 10); // 10ms间隔
        }
        
        printf("[LOG] 启动flag已发送到CAN总线 (ID: 0x%03X)\n", txf.can_id);
        sleep(1);
        return;
    }
    
    // 单帧发送
    write(s, &txf, sizeof(struct can_frame));
    printf("[LOG] 启动flag已发送到CAN总线 (ID: 0x%03X)\n", txf.can_id);
    
    // 等待一秒确保消息发送完成
    sleep(1);
}

// ISO-TP多帧发送（原始数据，无DID）
void send_isotp_response_raw(int s, const uint8_t *data, size_t data_len) {
    struct can_frame txf;
    txf.can_id = UDS_RESP_ID;
    
    if (data_len <= 7) {
        // 单帧发送
        txf.data[0] = data_len; // 单帧长度字段
        memcpy(&txf.data[1], data, data_len);
        txf.can_dlc = 1 + data_len;
        printf("[LOG] [ISOTP] 单帧发送: ");
        for (int i = 0; i < txf.can_dlc; ++i) printf("%02X ", txf.data[i]);
        printf("\n");
        write(s, &txf, sizeof(struct can_frame));
        return;
    }
    
    // 多帧发送
    // 1. 发送首帧
    txf.data[0] = 0x10 | ((data_len >> 8) & 0x0F);
    txf.data[1] = data_len & 0xFF;
    size_t first_frame_data = 6;
    memcpy(&txf.data[2], data, first_frame_data);
    txf.can_dlc = 8;
    printf("[LOG] [ISOTP] 首帧发送: ");
    for (int i = 0; i < txf.can_dlc; ++i) printf("%02X ", txf.data[i]);
    printf("\n");
    write(s, &txf, sizeof(struct can_frame));
    
    // 2. 等待FC帧
    if (!wait_fc_frame(s, 1000)) {
        printf("[LOG] [ISOTP] 未收到FC帧，终止多帧发送\n");
        return;
    }
    
    // 3. 发送连续帧
    size_t sent = first_frame_data;
    uint8_t sn = 1;
    while (sent < data_len) {
        txf.data[0] = 0x20 | (sn & 0x0F);
        size_t remain = data_len - sent;
        size_t chunk = remain > 7 ? 7 : remain;
        memcpy(&txf.data[1], data + sent, chunk);
        txf.can_dlc = 1 + chunk;
        printf("[LOG] [ISOTP] 连续帧SN=%d发送: ", sn);
        for (int i = 0; i < txf.can_dlc; ++i) printf("%02X ", txf.data[i]);
        printf("\n");
        write(s, &txf, sizeof(struct can_frame));
        sent += chunk;
        sn = (sn + 1) & 0x0F;
        usleep(1000 * 10);
    }
}

// ISO-TP多帧发送（严格流控）
int wait_fc_frame(int s, int timeout_ms) {
    struct can_frame rx;
    fd_set readfds;
    struct timeval tv;
    FD_ZERO(&readfds);
    FD_SET(s, &readfds);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    int ret = select(s + 1, &readfds, NULL, NULL, &tv);
    if (ret > 0 && FD_ISSET(s, &readfds)) {
        int nbytes = read(s, &rx, sizeof(struct can_frame));
        if (nbytes > 0 && rx.can_id == UDS_PHYS_ID && rx.data[0] == 0x30) {
            printf("[LOG] [ISOTP] 收到流控帧(FC): ");
            for (int i = 0; i < rx.can_dlc; ++i) printf("%02X ", rx.data[i]);
            printf("\n");
            return 1;
        } else {
            printf("[LOG] [ISOTP] 收到非FC帧或can_id不符，忽略\n");
        }
    } else {
        printf("[LOG] [ISOTP] 等待FC帧超时\n");
    }
    return 0;
}

// ISO-TP多帧发送
void send_isotp_response(int s, uint8_t sid, uint8_t *did, const char *data, size_t data_len) {
    struct can_frame txf;
    txf.can_id = UDS_RESP_ID;
    uint8_t uds_header[3];
    uds_header[0] = sid;
    uds_header[1] = did[0];
    uds_header[2] = did[1];
    size_t uds_header_len = 3;
    size_t total_len = uds_header_len + data_len;
    if (total_len <= 7) {
        txf.data[0] = 0x02 + data_len;
        memcpy(&txf.data[1], uds_header, uds_header_len);
        memcpy(&txf.data[1 + uds_header_len], data, data_len);
        txf.can_dlc = 1 + uds_header_len + data_len;
        printf("[LOG] [ISOTP] 单帧发送: ");
        for (int i = 0; i < txf.can_dlc; ++i) printf("%02X ", txf.data[i]);
        printf("\n");
        write(s, &txf, sizeof(struct can_frame));
        return;
    }
    // 多帧
    // 1. 发送首帧
    txf.data[0] = 0x10 | ((total_len >> 8) & 0x0F);
    txf.data[1] = total_len & 0xFF;
    size_t first_frame_data = 6;
    memcpy(&txf.data[2], uds_header, uds_header_len);
    size_t copy1 = first_frame_data - uds_header_len;
    memcpy(&txf.data[2 + uds_header_len], data, copy1);
    txf.can_dlc = 8;
    printf("[LOG] [ISOTP] 首帧发送: ");
    for (int i = 0; i < txf.can_dlc; ++i) printf("%02X ", txf.data[i]);
    printf("\n");
    write(s, &txf, sizeof(struct can_frame));
    // 2. 等待FC帧
    if (!wait_fc_frame(s, 1000)) {
        printf("[LOG] [ISOTP] 未收到FC帧，终止多帧发送\n");
        return;
    }
    // 3. 发送连续帧
    size_t sent = copy1;
    uint8_t sn = 1;
    while (sent < data_len) {
        txf.data[0] = 0x20 | (sn & 0x0F);
        size_t remain = data_len - sent;
        size_t chunk = remain > 7 ? 7 : remain;
        memcpy(&txf.data[1], data + sent, chunk);
        txf.can_dlc = 1 + chunk;
        printf("[LOG] [ISOTP] 连续帧SN=%d发送: ", sn);
        for (int i = 0; i < txf.can_dlc; ++i) printf("%02X ", txf.data[i]);
        printf("\n");
        write(s, &txf, sizeof(struct can_frame));
        sent += chunk;
        sn = (sn + 1) & 0x0F;
        usleep(1000 * 10);
    }
}

// 处理0x22服务
int handle_read_data_by_identifier(uint8_t *req, int req_len, uint8_t *resp, int *resp_len) {
    if (req_len < 3) {
        printf("[LOG] 0x22请求长度不足: %d\n", req_len);
        return -1;
    }
    uint16_t did = (req[1] << 8) | req[2];
    printf("[LOG] 0x22服务, DID=0x%04X, 安全状态: %s, 安全级别: %d\n", 
           did, security_unlocked ? "已解锁" : "未解锁", security_level);
    
    if (did == 0xF190) { // 公开flag - 无需安全访问
        printf("[LOG] 返回公开flag: %s\n", PUBLIC_FLAG);
        // 多帧发送
        return 2; // 特殊返回值，主循环处理
    } else if (did == 0xC1C2) { // 安全flag - 需要安全访问
        if (!security_unlocked) {
            printf("[LOG] 尝试访问安全DID但未解锁安全访问\n");
            resp[0] = 0x7F;
            resp[1] = 0x22;
            resp[2] = 0x33; // SecurityAccessDenied
            *resp_len = 3;
            return 0;
        }
        printf("[LOG] 返回安全flag: %s\n", SECURE_FLAG);
        // 多帧发送
        return 3; // 特殊返回值，主循环处理
    } else if (did == 0xD1D2) { // 高级flag - 需要级别3安全访问
        if (security_level < 3) {
            printf("[LOG] 尝试访问高级DID但安全级别不足 (当前: %d, 需要: 3)\n", security_level);
            resp[0] = 0x7F;
            resp[1] = 0x22;
            resp[2] = 0x33; // SecurityAccessDenied
            *resp_len = 3;
            return 0;
        }
        printf("[LOG] 返回高级flag: %s\n", ADVANCED_FLAG);
        // 多帧发送
        return 4; // 特殊返回值，主循环处理
    }
    printf("[LOG] 未知DID: 0x%04X\n", did);
    return -1;
}

// 处理0x10服务 - DiagnosticSessionControl
int handle_diagnostic_session_control(uint8_t *req, int req_len, uint8_t *resp, int *resp_len) {
    if (req_len < 2) {
        printf("[LOG] 0x10请求长度不足: %d\n", req_len);
        return -1;
    }
    uint8_t session_type = req[1];
    printf("[LOG] 0x10服务, 会话类型=0x%02X\n", session_type);
    
    if (session_type == 0x01) { // 默认会话
        current_session = 0x01;
        // 注意：安全访问状态在会话切换时保持不变
        // 只有ECU重启才会重置安全状态
        printf("[LOG] 切换到默认会话，安全状态保持不变\n");
        last_tester_present_time = 0; // 默认会话不需要维持
        resp[0] = 0x50; // 肯定响应
        resp[1] = 0x01; // 会话类型
        resp[2] = 0x00; // p2_server_max (50ms)
        resp[3] = 0x32; // p2_server_max (50ms)
        *resp_len = 4;
        return 0;
    } else if (session_type == 0x02) { // 编程会话
        current_session = 0x02;
        printf("[LOG] 切换到编程会话\n");
        last_tester_present_time = time(NULL); // 进入非默认会话，初始化计时
        resp[0] = 0x50; // 肯定响应
        resp[1] = 0x02; // 会话类型
        resp[2] = 0x00; // p2_server_max (50ms)
        resp[3] = 0x32; // p2_server_max (50ms)
        *resp_len = 4;
        return 0;
    } else {
        printf("[LOG] 不支持的会话类型: 0x%02X\n", session_type);
        resp[0] = 0x7F;
        resp[1] = 0x10;
        resp[2] = 0x12; // SubFunctionNotSupported
        *resp_len = 3;
        return 0;
    }
}

// 处理0x11服务 - ECUReset
int handle_ecu_reset(uint8_t *req, int req_len, uint8_t *resp, int *resp_len) {
    if (req_len < 2) {
        printf("[LOG] 0x11请求长度不足: %d\n", req_len);
        return -1;
    }
    uint8_t reset_type = req[1];
    printf("[LOG] 0x11服务, 复位类型=0x%02X\n", reset_type);
    
    if (reset_type == 0x01) { // HardReset
        printf("[LOG] 收到硬复位请求，准备重启程序...\n");
        resp[0] = 0x51; // 肯定响应
        resp[1] = 0x01; // 复位类型
        *resp_len = 2;
        
        // 发送响应后重启
        printf("[LOG] 发送复位响应，3秒后重启...\n");
        sleep(3);
        printf("[LOG] 正在重启UDS服务器...\n");
        exit(0); // 退出程序，Docker容器会自动重启
    } else {
        printf("[LOG] 不支持的复位类型: 0x%02X\n", reset_type);
        resp[0] = 0x7F;
        resp[1] = 0x11;
        resp[2] = 0x12; // SubFunctionNotSupported
        *resp_len = 3;
        return 0;
    }
}

// 处理0x27服务
int handle_security_access(uint8_t *req, int req_len, uint8_t *resp, int *resp_len) {
    if (req_len < 2) {
        printf("[LOG] 0x27请求长度不足: %d\n", req_len);
        return -1;
    }
    uint8_t subfunc = req[1];
    uint8_t level = subfunc & 0xFE; // 获取安全级别 (清除奇偶位)
    uint8_t is_request = subfunc & 0x01; // 判断是请求还是响应
    
    printf("[LOG] 0x27服务, subfunc=0x%02X, 级别=%d, 类型=%s\n", 
           subfunc, level, is_request ? "请求seed" : "提交key");
    
    // 检查会话要求
    if ((subfunc == 0x03 || subfunc == 0x04) && current_session != 0x02) { // 级别3需要编程会话
        printf("[LOG] 级别3安全访问需要编程会话\n");
        resp[0] = 0x7F;
        resp[1] = 0x27;
        resp[2] = 0x7E; // SubFunctionNotSupportedInActiveSession
        *resp_len = 3;
        return 0;
    }
    
    if (is_request) { // 请求seed
        if (subfunc == 0x01) { // 级别1请求seed
            g_seed = generate_seed();
            printf("[LOG] 级别1生成seed: 0x%08X\n", g_seed);
            resp[0] = 0x67;
            resp[1] = 0x01;
            resp[2] = (g_seed >> 24) & 0xFF;
            resp[3] = (g_seed >> 16) & 0xFF;
            resp[4] = (g_seed >> 8) & 0xFF;
            resp[5] = g_seed & 0xFF;
            *resp_len = 6;
            return 0;
        } else if (subfunc == 0x03) { // 级别3请求seed
            g_seed = generate_seed();
            printf("[LOG] 级别3生成seed: 0x%08X\n", g_seed);
            resp[0] = 0x67;
            resp[1] = 0x03; // 级别3请求seed
            resp[2] = (g_seed >> 24) & 0xFF;
            resp[3] = (g_seed >> 16) & 0xFF;
            resp[4] = (g_seed >> 8) & 0xFF;
            resp[5] = g_seed & 0xFF;
            *resp_len = 6;
            return 0;
        } else if (subfunc == 0x05) { // 级别5请求seed
            g_seed = generate_seed();
            printf("[LOG] 级别5生成seed: 0x%08X\n", g_seed);
            resp[0] = 0x67;
            resp[1] = 0x05; // 级别5请求seed
            resp[2] = (g_seed >> 24) & 0xFF;
            resp[3] = (g_seed >> 16) & 0xFF;
            resp[4] = (g_seed >> 8) & 0xFF;
            resp[5] = g_seed & 0xFF;
            *resp_len = 6;
            return 0;
        } else {
            printf("[LOG] 不支持的安全访问subfunction: 0x%02X\n", subfunc);
            resp[0] = 0x7F;
            resp[1] = 0x27;
            resp[2] = 0x12; // SubFunctionNotSupported
            *resp_len = 3;
            return 0;
        }
    } else { // 提交key
        if (req_len < 6) {
            printf("[LOG] key长度不足\n");
            return -1;
        }
        
        uint32_t key = (req[2] << 24) | (req[3] << 16) | (req[4] << 8) | req[5];
        
        if (subfunc == 0x02) { // 级别1发送key
            uint32_t expected_key = calc_key(g_seed);
            printf("[LOG] 级别1收到key: 0x%08X, 当前seed: 0x%08X, 正确key: 0x%08X\n", 
                   key, g_seed, expected_key);
            if (key == expected_key) {
                security_level = 1;
                security_unlocked = 1;
                printf("[LOG] 级别1安全访问解锁成功\n");
                resp[0] = 0x67;
                resp[1] = 0x02;
                *resp_len = 2;
                return 0;
            } else {
                printf("[LOG] 级别1安全访问key错误\n");
                resp[0] = 0x7F;
                resp[1] = 0x27;
                resp[2] = 0x35; // invalid key
                *resp_len = 3;
                return 0;
            }
        } else if (subfunc == 0x04) { // 级别3发送key
            uint32_t expected_key = calc_key_level3(g_seed);
            printf("[LOG] 级别3收到key: 0x%08X, 当前seed: 0x%08X, 正确key: 0x%08X\n", 
                   key, g_seed, expected_key);
            if (key == expected_key) {
                security_level = 3;
                security_unlocked = 1;
                printf("[LOG] 级别3安全访问解锁成功\n");
                resp[0] = 0x67;
                resp[1] = 0x04;
                *resp_len = 2;
                return 0;
            } else {
                printf("[LOG] 级别3安全访问key错误\n");
                resp[0] = 0x7F;
                resp[1] = 0x27;
                resp[2] = 0x35; // invalid key
                *resp_len = 3;
                return 0;
            }
        } else if (subfunc == 0x06) { // 级别5发送key
            uint32_t expected_key = calc_key_level5(g_seed);
            printf("[LOG] 级别5收到key: 0x%08X, 当前seed: 0x%08X, 正确key: 0x%08X\n", 
                   key, g_seed, expected_key);
            if (key == expected_key) {
                security_level = 5;
                security_unlocked = 1;
                printf("[LOG] 级别5安全访问解锁成功\n");
                resp[0] = 0x67;
                resp[1] = 0x06;
                *resp_len = 2;
                return 0;
            } else {
                printf("[LOG] 级别5安全访问key错误\n");
                resp[0] = 0x7F;
                resp[1] = 0x27;
                resp[2] = 0x35; // invalid key
                *resp_len = 3;
                return 0;
            }
        } else {
            printf("[LOG] 不支持的安全访问subfunction: 0x%02X\n", subfunc);
            resp[0] = 0x7F;
            resp[1] = 0x27;
            resp[2] = 0x12; // SubFunctionNotSupported
            *resp_len = 3;
            return 0;
        }
    }
}

// 处理0x23服务 - ReadMemoryByAddress
int handle_read_memory_by_address(uint8_t *req, int req_len, uint8_t *resp, int *resp_len) {
    printf("[LOG] ===== 0x23 ReadMemoryByAddress 服务开始 =====\n");
    
    // 1. 基本参数验证
    if (req_len < 5) {
        printf("[LOG] 错误: 请求长度不足 (%d < 5)\n", req_len);
        resp[0] = 0x7F;
        resp[1] = 0x23;
        resp[2] = 0x13; // IncorrectMessageLengthOrInvalidFormat
        *resp_len = 3;
        return 0;
    }
    
    // 2. 安全访问检查
    if (security_level < 5) {
        printf("[LOG] 错误: 安全级别不足 (当前: %d, 需要: 5)\n", security_level);
        resp[0] = 0x7F;
        resp[1] = 0x23;
        resp[2] = 0x33; // SecurityAccessDenied
        *resp_len = 3;
        return 0;
    }
    
    printf("[LOG] 安全访问检查通过 (级别: %d)\n", security_level);
    
    // 3. 解析格式标识符
    uint8_t format_identifier = req[1];  // 格式标识符
    
    printf("[LOG] 格式标识符: 0x%02X\n", format_identifier);
    
    // 4. 解析地址和大小字段长度
    uint8_t size_len = (format_identifier >> 4) & 0x0F;  // 大小字段长度（高4位）
    uint8_t addr_len = format_identifier & 0x0F;         // 地址字段长度（低4位）
    
    printf("[LOG] 字段长度: 地址=%d字节, 大小=%d字节\n", addr_len, size_len);
    
    // 5. 验证请求长度
    int expected_len = 2 + addr_len + size_len;  // 2字节头部 + 地址 + 大小
    if (req_len < expected_len) {
        printf("[LOG] 错误: 请求长度不匹配 (实际: %d, 期望: %d)\n", req_len, expected_len);
        resp[0] = 0x7F;
        resp[1] = 0x23;
        resp[2] = 0x13; // IncorrectMessageLengthOrInvalidFormat
        *resp_len = 3;
        return 0;
    }
    
    // 6. 解析内存地址
    uint32_t address = 0;
    for (int i = 0; i < addr_len; i++) {
        address = (address << 8) | req[2 + i];
    }
    
    printf("[LOG] 解析地址: 0x%08X\n", address);
    
    // 7. 解析读取大小
    uint32_t size = 0;
    for (int i = 0; i < size_len; i++) {
        size = (size << 8) | req[2 + addr_len + i];
    }
    
    printf("[LOG] 读取参数: 地址=0x%08X, 大小=%d字节\n", address, size);
    
    // 8. 地址范围检查
    if (address < 0x40000000 || address > 0x4FFFFFFF) {
        printf("[LOG] 错误: 地址超出安全范围 (0x40000000-0x4FFFFFFF)\n");
        resp[0] = 0x7F;
        resp[1] = 0x23;
        resp[2] = 0x22; // ConditionsNotCorrect
        *resp_len = 3;
        return 0;
    }
    
    // 9. 大小限制检查
    if (size > 0x1000) { // 最大4KB
        printf("[LOG] 错误: 读取大小超出限制 (%d > 4096)\n", size);
        resp[0] = 0x7F;
        resp[1] = 0x23;
        resp[2] = 0x22; // ConditionsNotCorrect
        *resp_len = 3;
        return 0;
    }
    
    // 10. 程序内存范围检查
    if (address < 0x40000000 || address > 0x7FFFFFFF) {
        printf("[LOG] 错误: 地址超出程序内存范围\n");
        resp[0] = 0x7F;
        resp[1] = 0x23;
        resp[2] = 0x22; // ConditionsNotCorrect
        *resp_len = 3;
        return 0;
    }
    
    printf("[LOG] 所有检查通过，开始读取内存...\n");
    
    // 11. 执行内存读取
    uint8_t *memory_ptr = (uint8_t *)address;
    
    // 12. 构造响应头
    resp[0] = 0x63; // ReadMemoryByAddress响应
    resp[1] = format_identifier; // 返回相同的格式标识符
    
    // 13. 复制内存数据
    uint8_t *data_ptr = &resp[2];
    // 修改：严格按照size返回数据，最大不超过4KB（0x1000）
    uint32_t copy_size = size; // 按请求的size返回
    if (copy_size > 0x1000) copy_size = 0x1000; // 冗余保护，实际前面已检查

    // 安全地复制内存数据 - 添加更严格的检查
    if (copy_size > 0) {
        // 检查地址是否在有效的程序内存范围内
        if (address < 0x40000000 || address > 0x7FFFFFFF) {
            printf("[LOG] 错误: 地址超出有效范围，拒绝访问\n");
            resp[0] = 0x7F;
            resp[1] = 0x23;
            resp[2] = 0x22; // ConditionsNotCorrect
            *resp_len = 3;
            return 0;
        }
        
        // 检查地址是否对齐（可选，但有助于避免某些问题）
        if (address % 4 != 0) {
            printf("[LOG] 警告: 地址未对齐 (0x%08X %% 4 = %d)\n", address, address % 4);
        }
        
        // 尝试安全地读取内存
        printf("[LOG] 尝试读取内存地址: 0x%08X\n", address);
        
        // 特殊处理：当访问0x40000000时，返回ELF文件数据而不是真正读取内存
        if (address >= 0x40000000 && g_elf_data != NULL) {
            uint32_t elf_offset = address - 0x40000000;
            if (elf_offset < g_elf_size) {
                // 从ELF数据中复制
                uint32_t available_size = g_elf_size - elf_offset;
                uint32_t actual_copy_size = (copy_size < available_size) ? copy_size : available_size;
                
                printf("[LOG] 从ELF文件数据返回: 偏移=0x%08X, 大小=%d字节\n", elf_offset, actual_copy_size);
                memcpy(data_ptr, g_elf_data + elf_offset, actual_copy_size);
                
                // 如果请求的大小超过了ELF文件大小，用零填充剩余部分
                if (copy_size > actual_copy_size) {
                    printf("[LOG] 用零填充剩余 %d 字节\n", copy_size - actual_copy_size);
                    memset(data_ptr + actual_copy_size, 0, copy_size - actual_copy_size);
                }
            } else {
                // 超出ELF文件范围，返回零数据
                printf("[LOG] 地址超出ELF文件范围，返回零数据\n");
                memset(data_ptr, 0, copy_size);
            }
        } else {
            // 对于其他地址，尝试读取内存，如果失败则返回零数据
            uint8_t *memory_ptr = (uint8_t *)address;
            if (address < 0x40000000 || address > 0x7FFFFFFF) {
                printf("[LOG] 地址无效，返回零数据\n");
                memset(data_ptr, 0, copy_size);
            } else {
                memcpy(data_ptr, memory_ptr, copy_size);
            }
        }
    }
    
    // 14. 输出调试信息
    printf("[LOG] 内存读取成功: 复制了%d字节\n", copy_size);
    printf("[LOG] 内存数据 (前16字节): ");
    for (int i = 0; i < 16 && i < copy_size; i++) {
        printf("%02X ", data_ptr[i]);
    }
    printf("\n");
    
    // 15. 检查是否包含flag
    char *data_str = (char *)data_ptr;
    if (strstr(data_str, "UDSCTF{") != NULL) {
        printf("[LOG] *** 发现flag字符串! ***\n");
    }
    
    // 16. 设置响应长度
    *resp_len = 2 + copy_size;
    
    printf("[LOG] ===== 0x23 ReadMemoryByAddress 服务完成 =====\n");
    return 0;
}

int handle_tester_present(uint8_t *req, int req_len, uint8_t *resp, int *resp_len) {
    last_tester_present_time = time(NULL);
    printf("[LOG] 收到TesterPresent，更新时间戳\n");
    resp[0] = 0x7E;
    resp[1] = 0x00;
    *resp_len = 2;
    return 0;
}

int main() {
    int s;
    struct sockaddr_can addr;
    struct ifreq ifr;
    struct can_frame frame;
    srand(time(NULL));
    
    // 设置信号处理
    signal(SIGSEGV, segfault_handler);
    signal(SIGBUS, segfault_handler);
    
    // 显示程序内存布局信息
    printf("=== UDS服务器内存布局 ===\n");
    printf("程序基址: 0x%08X\n", (unsigned int)main);
    printf("PUBLIC_FLAG地址: 0x%08X\n", (unsigned int)PUBLIC_FLAG);
    printf("SECURE_FLAG地址: 0x%08X\n", (unsigned int)SECURE_FLAG);
    printf("ADVANCED_FLAG地址: 0x%08X\n", (unsigned int)ADVANCED_FLAG);
    printf("BOOT_FLAG地址: 0x%08X\n", (unsigned int)BOOT_FLAG);
    printf("MEMORY_FLAG地址: 0x%08X\n", (unsigned int)MEMORY_FLAG);
    printf("========================\n\n");

    if ((s = socket(PF_CAN, SOCK_RAW, CAN_RAW)) < 0) {
        perror("socket");
        return 1;
    }
    strcpy(ifr.ifr_name, "vcan0");
    ioctl(s, SIOCGIFINDEX, &ifr);
    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;
    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    printf("UDS server started on vcan0...\n");
    
    // 发送启动flag
    send_boot_flag(s);
    
    // 读取自身ELF文件内容到全局变量
    FILE *elf_file = fopen("uds_server", "rb");
    if (elf_file) {
        fseek(elf_file, 0, SEEK_END);
        g_elf_size = ftell(elf_file);
        fseek(elf_file, 0, SEEK_SET);
        g_elf_data = (uint8_t *)malloc(g_elf_size);
        if (g_elf_data) {
            fread(g_elf_data, 1, g_elf_size, elf_file);
            fclose(elf_file);
            printf("[LOG] 成功读取ELF文件 'uds_server' (大小: %zu bytes)\n", g_elf_size);
        } else {
            perror("malloc");
            fclose(elf_file);
            return 1;
        }
    } else {
        perror("fopen");
        return 1;
    }

    while (1) {
        // 会话超时检查
        if (current_session != 0x01 && last_tester_present_time > 0) {
            time_t now = time(NULL);
            if (now - last_tester_present_time > 10) {
                printf("[LOG] 会话超时，自动回退到默认会话\n");
                current_session = 0x01;
                // 注意：安全访问状态在默认会话中仍然有效
                // security_level 和 security_unlocked 保持不变
                last_tester_present_time = 0;
            }
        }
        int nbytes = read(s, &frame, sizeof(struct can_frame));
        if (nbytes < 0) continue;
        printf("[LOG] 收到CAN帧: can_id=0x%03X, dlc=%d, data=", frame.can_id, frame.can_dlc);
        for (int i = 0; i < frame.can_dlc; ++i) printf("%02X ", frame.data[i]);
        printf("\n");
        if (frame.can_id != UDS_PHYS_ID) {
            printf("[LOG] 非UDS物理寻址帧，忽略\n");
            continue;
        }
        
        // 解析ISO-TP长度字段
        uint8_t frame_type = (frame.data[0] >> 4) & 0x0F;
        uint8_t data_length = frame.data[0] & 0x0F;
        uint8_t *uds_data = NULL;
        int uds_data_len = 0;
        
        printf("[LOG] ISO-TP帧类型: 0x%X, 数据长度: %d\n", frame_type, data_length);
        
        if (frame_type == 0x0) { // 单帧
            if (data_length > 0 && data_length <= 7) {
                uds_data = &frame.data[1];
                uds_data_len = data_length;
                printf("[LOG] 单帧UDS数据: ");
                for (int i = 0; i < uds_data_len; ++i) printf("%02X ", uds_data[i]);
                printf("\n");
            } else {
                printf("[LOG] 单帧数据长度无效: %d\n", data_length);
                continue;
            }
        } else if (frame_type == 0x1) { // 首帧
            printf("[LOG] 收到首帧，开始多帧处理\n");
            
            // 解析首帧长度
            uint16_t total_length = ((frame.data[0] & 0x0F) << 8) | frame.data[1];
            printf("[LOG] 多帧总长度: %d字节\n", total_length);
            
            // 分配缓冲区
            uint8_t *multi_frame_data = malloc(total_length);
            if (!multi_frame_data) {
                printf("[LOG] 内存分配失败\n");
                continue;
            }
            
            // 复制首帧数据
            int first_frame_data_len = 6; // 首帧数据长度
            memcpy(multi_frame_data, &frame.data[2], first_frame_data_len);
            
            // 发送流控帧
            struct can_frame fc_frame;
            fc_frame.can_id = UDS_PHYS_ID;
            fc_frame.data[0] = 0x30; // 流控帧
            fc_frame.data[1] = 0x00; // 块大小
            fc_frame.data[2] = 0x00; // STmin
            fc_frame.can_dlc = 3;
            write(s, &fc_frame, sizeof(struct can_frame));
            printf("[LOG] 发送流控帧\n");
            
            // 接收连续帧
            int received_len = first_frame_data_len;
            uint8_t sn = 1;
            
            while (received_len < total_length) {
                int nbytes = read(s, &frame, sizeof(struct can_frame));
                if (nbytes < 0) break;
                
                if (frame.can_id == UDS_PHYS_ID) {
                    uint8_t cf_frame_type = (frame.data[0] >> 4) & 0x0F;
                    if (cf_frame_type == 0x2) { // 连续帧
                        uint8_t received_sn = frame.data[0] & 0x0F;
                        if (received_sn == sn) {
                            int cf_data_len = frame.can_dlc - 1;
                            int copy_len = (total_length - received_len < cf_data_len) ? 
                                          (total_length - received_len) : cf_data_len;
                            
                            memcpy(multi_frame_data + received_len, &frame.data[1], copy_len);
                            received_len += copy_len;
                            sn = (sn + 1) & 0x0F;
                            
                            printf("[LOG] 收到连续帧SN=%d, 已接收%d/%d字节\n", 
                                   received_sn, received_len, total_length);
                        }
                    }
                }
            }
            
            if (received_len == total_length) {
                uds_data = multi_frame_data;
                uds_data_len = total_length;
                printf("[LOG] 多帧接收完成，UDS数据: ");
                for (int i = 0; i < uds_data_len; ++i) printf("%02X ", uds_data[i]);
                printf("\n");
            } else {
                printf("[LOG] 多帧接收失败\n");
                free(multi_frame_data);
                continue;
            }
        } else if (frame_type == 0x2) { // 连续帧（单独收到）
            printf("[LOG] 收到连续帧，但未在首帧处理中\n");
            continue;
        } else if (frame_type == 0x3) { // 流控帧
            printf("[LOG] 收到流控帧，忽略\n");
            continue;
        } else {
            printf("[LOG] 未知帧类型: 0x%X\n", frame_type);
            continue;
        }
        
        if (uds_data == NULL || uds_data_len == 0) {
            printf("[LOG] 无有效UDS数据\n");
            continue;
        }
        
        uint8_t resp[64];
        int resp_len = 0;
        int handled = 0;
        
        if (uds_data[0] == 0x10) {
            handled = handle_diagnostic_session_control(uds_data, uds_data_len, resp, &resp_len);
        } else if (uds_data[0] == 0x11) {
            handled = handle_ecu_reset(uds_data, uds_data_len, resp, &resp_len);
        } else if (uds_data[0] == 0x22) {
            handled = handle_read_data_by_identifier(uds_data, uds_data_len, resp, &resp_len);
            if (handled == 2) {
                uint8_t did[2] = {uds_data[1], uds_data[2]};
                send_isotp_response(s, 0x62, did, PUBLIC_FLAG, strlen(PUBLIC_FLAG));
                continue;
            } else if (handled == 3) {
                uint8_t did[2] = {uds_data[1], uds_data[2]};
                send_isotp_response(s, 0x62, did, SECURE_FLAG, strlen(SECURE_FLAG));
                continue;
            } else if (handled == 4) {
                uint8_t did[2] = {uds_data[1], uds_data[2]};
                send_isotp_response(s, 0x62, did, ADVANCED_FLAG, strlen(ADVANCED_FLAG));
                continue;
            }
        } else if (uds_data[0] == 0x23) {
            handled = handle_read_memory_by_address(uds_data, uds_data_len, resp, &resp_len);
        } else if (uds_data[0] == 0x27) {
            handled = handle_security_access(uds_data, uds_data_len, resp, &resp_len);
        } else if (uds_data[0] == 0x3E) {
            handled = handle_tester_present(uds_data, uds_data_len, resp, &resp_len);
        } else {
            printf("[LOG] 未实现的服务号: 0x%02X\n", uds_data[0]);
        }
        
        if (handled == 0 && resp_len > 0) {
            // 检查响应长度，如果超过单帧限制，使用多帧发送
            if (resp_len <= 7) {
                // 单帧发送
                struct can_frame txf;
                txf.can_id = UDS_RESP_ID;
                txf.data[0] = resp_len; // 单帧，长度字段
                memcpy(&txf.data[1], resp, resp_len);
                txf.can_dlc = 1 + resp_len;
                printf("[LOG] 发送单帧响应: can_id=0x%03X, dlc=%d, data=", txf.can_id, txf.can_dlc);
                for (int i = 0; i < txf.can_dlc; ++i) printf("%02X ", txf.data[i]);
                printf("\n");
                write(s, &txf, sizeof(struct can_frame));
            } else {
                // 多帧发送
                printf("[LOG] 响应长度超过单帧限制(%d字节)，使用多帧发送\n", resp_len);
                send_isotp_response_raw(s, resp, resp_len);
            }
        } else if (handled != 0) {
            printf("[LOG] 未处理/错误的请求\n");
        }
        
        // 释放多帧数据内存
        if (frame_type == 0x1 && uds_data != NULL) {
            free(uds_data);
        }
    }
    close(s);
    return 0;
} 