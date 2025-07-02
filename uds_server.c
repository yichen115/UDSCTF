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
#include "iso14229.h" // 假设你已有iso14229协议栈
#include <time.h>
#include <sys/select.h>

#define FLAG "CTF{UDS_CAN_FLAG}"
#define VIN_FLAG "CTF{UDS_CAN_FLAG}"
#define UDS_PHYS_ID 0x7E0
#define UDS_RESP_ID 0x7E8

static uint32_t g_seed = 0;
static int security_unlocked = 0;

uint32_t generate_seed() {
    return (uint32_t)rand();
}

uint32_t calc_key(uint32_t seed) {
    return seed ^ 0xdeadbeef;
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
    printf("[LOG] 0x22服务, DID=0x%04X\n", did);
    if (did == 0xF190) { // VIN
        printf("[LOG] 返回VIN/flag: %s\n", VIN_FLAG);
        // 多帧发送
        return 2; // 特殊返回值，主循环处理
    }
    printf("[LOG] 未知DID: 0x%04X\n", did);
    return -1;
}

// 处理0x27服务
int handle_security_access(uint8_t *req, int req_len, uint8_t *resp, int *resp_len) {
    if (req_len < 2) {
        printf("[LOG] 0x27请求长度不足: %d\n", req_len);
        return -1;
    }
    uint8_t subfunc = req[1];
    printf("[LOG] 0x27服务, subfunc=0x%02X\n", subfunc);
    if (subfunc == 0x01) { // 请求seed
        g_seed = generate_seed();
        printf("[LOG] 生成seed: 0x%08X\n", g_seed);
        resp[0] = 0x67;
        resp[1] = 0x01;
        resp[2] = (g_seed >> 24) & 0xFF;
        resp[3] = (g_seed >> 16) & 0xFF;
        resp[4] = (g_seed >> 8) & 0xFF;
        resp[5] = g_seed & 0xFF;
        *resp_len = 6;
        return 0;
    } else if (subfunc == 0x02 && req_len >= 6) { // 提交key
        uint32_t key = (req[2] << 24) | (req[3] << 16) | (req[4] << 8) | req[5];
        printf("[LOG] 收到key: 0x%08X, 当前seed: 0x%08X, 正确key: 0x%08X\n", key, g_seed, calc_key(g_seed));
        if (key == calc_key(g_seed)) {
            security_unlocked = 1;
            printf("[LOG] 安全访问解锁成功\n");
            resp[0] = 0x67;
            resp[1] = 0x02;
            *resp_len = 2;
            return 0;
        } else {
            printf("[LOG] 安全访问key错误\n");
            resp[0] = 0x7F;
            resp[1] = 0x27;
            resp[2] = 0x35; // invalid key
            *resp_len = 3;
            return 0;
        }
    }
    printf("[LOG] 未知subfunc或长度不足\n");
    return -1;
}

int main() {
    int s;
    struct sockaddr_can addr;
    struct ifreq ifr;
    struct can_frame frame;
    srand(time(NULL));

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
    while (1) {
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
            printf("[LOG] 收到首帧，暂不支持多帧处理\n");
            continue;
        } else if (frame_type == 0x2) { // 连续帧
            printf("[LOG] 收到连续帧，暂不支持多帧处理\n");
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
        
        if (uds_data[0] == 0x22) {
            handled = handle_read_data_by_identifier(uds_data, uds_data_len, resp, &resp_len);
            if (handled == 2) {
                // 多帧发送
                uint8_t did[2] = {uds_data[1], uds_data[2]};
                send_isotp_response(s, 0x62, did, VIN_FLAG, strlen(VIN_FLAG));
                continue;
            }
        } else if (uds_data[0] == 0x27) {
            handled = handle_security_access(uds_data, uds_data_len, resp, &resp_len);
        } else {
            printf("[LOG] 未实现的服务号: 0x%02X\n", uds_data[0]);
        }
        
        if (handled == 0 && resp_len > 0) {
            struct can_frame txf;
            txf.can_id = UDS_RESP_ID;
            // 添加ISO-TP长度字段
            txf.data[0] = resp_len; // 单帧，长度字段
            memcpy(&txf.data[1], resp, resp_len);
            txf.can_dlc = 1 + resp_len;
            printf("[LOG] 发送响应: can_id=0x%03X, dlc=%d, data=", txf.can_id, txf.can_dlc);
            for (int i = 0; i < txf.can_dlc; ++i) printf("%02X ", txf.data[i]);
            printf("\n");
            write(s, &txf, sizeof(struct can_frame));
        } else if (handled != 0) {
            printf("[LOG] 未处理/错误的请求\n");
        }
    }
    close(s);
    return 0;
} 