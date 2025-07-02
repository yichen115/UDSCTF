#include "iso14229.h"

#ifdef UDS_LINES
#line 1 "src/client.c"
#endif





enum UDSClientRequestState {
    kRequestStateIdle = 0,
    kRequestStateSending,
    kRequestStateAwaitSendComplete,
    kRequestStateAwaitResponse,
    kRequestStateProcessResponse,
};

UDSErr_t UDSClientInit(UDSClient_t *client) {
    if (NULL == client) {
        return UDS_ERR_INVALID_ARG;
    }
    memset(client, 0, sizeof(*client));
    client->state = kRequestStateIdle;

    client->p2_ms = UDS_CLIENT_DEFAULT_P2_MS;
    client->p2_star_ms = UDS_CLIENT_DEFAULT_P2_STAR_MS;

    if (client->p2_star_ms < client->p2_ms) {
        fprintf(stderr, "p2_star_ms must be >= p2_ms");
        client->p2_star_ms = client->p2_ms;
    }

    return UDS_OK;
}

static const char *ClientStateName(enum UDSClientRequestState state) {
    switch (state) {
    case kRequestStateIdle:
        return "Idle";
    case kRequestStateSending:
        return "Sending";
    case kRequestStateAwaitSendComplete:
        return "AwaitSendComplete";
    case kRequestStateAwaitResponse:
        return "AwaitResponse";
    case kRequestStateProcessResponse:
        return "ProcessResponse";
    default:
        return "Unknown";
    }
}

static void changeState(UDSClient_t *client, enum UDSClientRequestState state) {
    if (state != client->state) {
        UDS_LOGI(__FILE__, "client state: %s (%d) -> %s (%d)", ClientStateName(client->state),
                 client->state, ClientStateName(state), state);

        client->state = state;

        switch (state) {
        case kRequestStateIdle:
            client->fn(client, UDS_EVT_Idle, NULL);
            break;
        default:
            break;
        }
    }
}

/**
 * @brief Check that the response is a valid UDS response
 * @param client
 * @return UDSErr_t
 */
static UDSErr_t ValidateServerResponse(const UDSClient_t *client) {

    if (client->recv_size < 1) {
        return UDS_ERR_RESP_TOO_SHORT;
    }

    if (0x7F == client->recv_buf[0]) { // Negative response
        if (client->recv_size < 2) {
            return UDS_ERR_RESP_TOO_SHORT;
        } else if (client->send_buf[0] != client->recv_buf[1]) {
            return UDS_ERR_SID_MISMATCH;
        } else if (UDS_NRC_RequestCorrectlyReceived_ResponsePending == client->recv_buf[2]) {
            return UDS_OK;
        } else {
            return client->recv_buf[2];
        }

    } else { // Positive response
        if (UDS_RESPONSE_SID_OF(client->send_buf[0]) != client->recv_buf[0]) {
            return UDS_ERR_SID_MISMATCH;
        }
        switch (client->send_buf[0]) {
        case kSID_ECU_RESET:
            if (client->recv_size < 2) {
                return UDS_ERR_RESP_TOO_SHORT;
            } else if (client->send_buf[1] != client->recv_buf[1]) {
                return UDS_ERR_SUBFUNCTION_MISMATCH;
            } else {
                ;
            }
            break;
        }
    }

    return UDS_OK;
}

/**
 * @brief Handle validated server response
 * @param client
 */
static UDSErr_t HandleServerResponse(UDSClient_t *client) {
    if (0x7F == client->recv_buf[0]) {
        if (UDS_NRC_RequestCorrectlyReceived_ResponsePending == client->recv_buf[2]) {
            client->p2_timer = UDSMillis() + client->p2_star_ms;
            UDS_LOGI(__FILE__, "got RCRRP, set p2 timer to %u", client->p2_timer);
            memset(client->recv_buf, 0, client->recv_buf_size);
            client->recv_size = 0;
            UDSTpAckRecv(client->tp);
            changeState(client, kRequestStateAwaitResponse);
            return UDS_NRC_RequestCorrectlyReceived_ResponsePending;
        } else {
            ;
        }
    } else {
        uint8_t respSid = client->recv_buf[0];
        switch (UDS_REQUEST_SID_OF(respSid)) {
        case kSID_DIAGNOSTIC_SESSION_CONTROL: {
            if (client->recv_size < UDS_0X10_RESP_LEN) {
                UDS_LOGI(__FILE__, "Error: SID %x response too short",
                         kSID_DIAGNOSTIC_SESSION_CONTROL);
                UDSTpAckRecv(client->tp);
                changeState(client, kRequestStateIdle);
                return UDS_ERR_RESP_TOO_SHORT;
            }

            if (client->_options_copy & UDS_IGNORE_SRV_TIMINGS) {
                UDSTpAckRecv(client->tp);
                changeState(client, kRequestStateIdle);
                return UDS_OK;
            }

            uint16_t p2 = (client->recv_buf[2] << 8) + client->recv_buf[3];
            uint32_t p2_star = ((client->recv_buf[4] << 8) + client->recv_buf[5]) * 10;
            UDS_LOGI(__FILE__, "received new timings: p2: %" PRIu16 ", p2*: %" PRIu32, p2, p2_star);
            client->p2_ms = p2;
            client->p2_star_ms = p2_star;
            break;
        }
        default:
            break;
        }
    }
    UDSTpAckRecv(client->tp);
    return UDS_OK;
}

/**
 * @brief execute the client request state machine
 * @param client
 */
static UDSErr_t PollLowLevel(UDSClient_t *client) {
    UDSErr_t err = UDS_OK;
    UDS_ASSERT(client);

    if (NULL == client || NULL == client->tp || NULL == client->tp->poll) {
        return UDS_ERR_MISUSE;
    }

    UDSTpStatus_t tp_status = UDSTpPoll(client->tp);
    switch (client->state) {
    case kRequestStateIdle: {
        client->options = client->defaultOptions;
        break;
    }
    case kRequestStateSending: {
        UDSTpAddr_t ta_type = client->_options_copy & UDS_FUNCTIONAL ? UDS_A_TA_TYPE_FUNCTIONAL
                                                                     : UDS_A_TA_TYPE_PHYSICAL;
        UDSSDU_t info = {
            .A_Mtype = UDS_A_MTYPE_DIAG,
            .A_TA_Type = ta_type,
        };
        ssize_t ret = UDSTpSend(client->tp, client->send_buf, client->send_size, &info);
        if (ret < 0) {
            err = UDS_ERR_TPORT;
            UDS_LOGI(__FILE__, "tport err: %zd", ret);
        } else if (0 == ret) {
            UDS_LOGI(__FILE__, "send in progress...");
            ; // 等待发送成功
        } else if (client->send_size == ret) {
            changeState(client, kRequestStateAwaitSendComplete);
        } else {
            err = UDS_ERR_BUFSIZ;
        }
        break;
    }
    case kRequestStateAwaitSendComplete: {
        if (client->_options_copy & UDS_FUNCTIONAL) {
            // "The Functional addressing is applied only to single frame transmission"
            // Specification of Diagnostic Communication (Diagnostic on CAN - Network Layer)
            changeState(client, kRequestStateIdle);
        }
        if (tp_status & UDS_TP_SEND_IN_PROGRESS) {
            ; // await send complete
        } else {
            client->fn(client, UDS_EVT_SendComplete, NULL);
            if (client->_options_copy & UDS_SUPPRESS_POS_RESP) {
                changeState(client, kRequestStateIdle);
            } else {
                changeState(client, kRequestStateAwaitResponse);
                client->p2_timer = UDSMillis() + client->p2_ms;
            }
        }
        break;
    }
    case kRequestStateAwaitResponse: {
        UDSSDU_t info = {0};
        ssize_t len = UDSTpPeek(client->tp, &client->recv_buf, &info);

        if (UDS_A_TA_TYPE_FUNCTIONAL == info.A_TA_Type) {
            UDSTpAckRecv(client->tp);
            break;
        }
        if (len < 0) {
            err = UDS_ERR_TPORT;
            changeState(client, kRequestStateIdle);
        } else if (0 == len) {
            if (UDSTimeAfter(UDSMillis(), client->p2_timer)) {
                UDS_LOGI(__FILE__, "p2 timeout");
                err = UDS_ERR_TIMEOUT;
                changeState(client, kRequestStateIdle);
            }
        } else {
            UDS_LOGI(__FILE__, "received %zd bytes. Processing...", len);
            client->recv_size = len;

            err = ValidateServerResponse(client);
            if (UDS_OK == err) {
                err = HandleServerResponse(client);
            }

            if (UDS_OK == err) {
                client->fn(client, UDS_EVT_ResponseReceived, NULL);
                changeState(client, kRequestStateIdle);
            }

            UDSTpAckRecv(client->tp);
        }
        break;
    }

    default:
        UDS_ASSERT(0);
    }
    return err;
}

static UDSErr_t SendRequest(UDSClient_t *client) {
    client->_options_copy = client->options;

    if (client->_options_copy & UDS_SUPPRESS_POS_RESP) {
        // UDS-1:2013 8.2.2 Table 11
        client->send_buf[1] |= 0x80;
    }

    changeState(client, kRequestStateSending);
    UDSErr_t err = PollLowLevel(client); // poll once to begin sending immediately
    return err;
}

static UDSErr_t PreRequestCheck(UDSClient_t *client) {
    if (NULL == client) {
        return UDS_ERR_INVALID_ARG;
    }
    if (kRequestStateIdle != client->state) {
        return UDS_ERR_BUSY;
    }

    client->recv_size = 0;
    client->send_size = 0;

    if (client->tp == NULL) {
        return UDS_ERR_TPORT;
    }
    ssize_t ret = UDSTpGetSendBuf(client->tp, &client->send_buf);
    if (ret < 0) {
        return UDS_ERR_TPORT;
    }
    client->send_buf_size = ret;
    return UDS_OK;
}

UDSErr_t UDSSendBytes(UDSClient_t *client, const uint8_t *data, uint16_t size) {
    UDSErr_t err = PreRequestCheck(client);
    if (err) {
        return err;
    }
    if (size > client->send_buf_size) {
        return UDS_ERR_BUFSIZ;
    }
    memmove(client->send_buf, data, size);
    client->send_size = size;
    return SendRequest(client);
}

UDSErr_t UDSSendECUReset(UDSClient_t *client, UDSECUReset_t type) {
    UDSErr_t err = PreRequestCheck(client);
    if (err) {
        return err;
    }
    client->send_buf[0] = kSID_ECU_RESET;
    client->send_buf[1] = type;
    client->send_size = 2;
    return SendRequest(client);
}

UDSErr_t UDSSendDiagSessCtrl(UDSClient_t *client, enum UDSDiagnosticSessionType mode) {
    UDSErr_t err = PreRequestCheck(client);
    if (err) {
        return err;
    }
    client->send_buf[0] = kSID_DIAGNOSTIC_SESSION_CONTROL;
    client->send_buf[1] = mode;
    client->send_size = 2;
    return SendRequest(client);
}

UDSErr_t UDSSendCommCtrl(UDSClient_t *client, enum UDSCommunicationControlType ctrl,
                         enum UDSCommunicationType comm) {
    UDSErr_t err = PreRequestCheck(client);
    if (err) {
        return err;
    }
    client->send_buf[0] = kSID_COMMUNICATION_CONTROL;
    client->send_buf[1] = ctrl;
    client->send_buf[2] = comm;
    client->send_size = 3;
    return SendRequest(client);
}

UDSErr_t UDSSendTesterPresent(UDSClient_t *client) {
    UDSErr_t err = PreRequestCheck(client);
    if (err) {
        return err;
    }
    client->send_buf[0] = kSID_TESTER_PRESENT;
    client->send_buf[1] = 0;
    client->send_size = 2;
    return SendRequest(client);
}

UDSErr_t UDSSendRDBI(UDSClient_t *client, const uint16_t *didList,
                     const uint16_t numDataIdentifiers) {
    UDSErr_t err = PreRequestCheck(client);
    if (err) {
        return err;
    }
    if (NULL == didList || 0 == numDataIdentifiers) {
        return UDS_ERR_INVALID_ARG;
    }
    client->send_buf[0] = kSID_READ_DATA_BY_IDENTIFIER;
    for (int i = 0; i < numDataIdentifiers; i++) {
        uint16_t offset = 1 + sizeof(uint16_t) * i;
        if (offset + 2 > client->send_buf_size) {
            return UDS_ERR_INVALID_ARG;
        }
        (client->send_buf + offset)[0] = (didList[i] & 0xFF00) >> 8;
        (client->send_buf + offset)[1] = (didList[i] & 0xFF);
    }
    client->send_size = 1 + (numDataIdentifiers * sizeof(uint16_t));
    return SendRequest(client);
}

UDSErr_t UDSSendWDBI(UDSClient_t *client, uint16_t dataIdentifier, const uint8_t *data,
                     uint16_t size) {
    UDSErr_t err = PreRequestCheck(client);
    if (err) {
        return err;
    }
    if (data == NULL || size == 0) {
        return UDS_ERR_INVALID_ARG;
    }
    client->send_buf[0] = kSID_WRITE_DATA_BY_IDENTIFIER;
    if (client->send_buf_size <= 3 || size > client->send_buf_size - 3) {
        return UDS_ERR_BUFSIZ;
    }
    client->send_buf[1] = (dataIdentifier & 0xFF00) >> 8;
    client->send_buf[2] = (dataIdentifier & 0xFF);
    memmove(&client->send_buf[3], data, size);
    client->send_size = 3 + size;
    return SendRequest(client);
}

/**
 * @brief RoutineControl
 *
 * @param client
 * @param type
 * @param routineIdentifier
 * @param data
 * @param size
 * @return UDSErr_t
 * @addtogroup routineControl_0x31
 */
UDSErr_t UDSSendRoutineCtrl(UDSClient_t *client, enum RoutineControlType type,
                            uint16_t routineIdentifier, const uint8_t *data, uint16_t size) {
    UDSErr_t err = PreRequestCheck(client);
    if (err) {
        return err;
    }
    client->send_buf[0] = kSID_ROUTINE_CONTROL;
    client->send_buf[1] = type;
    client->send_buf[2] = routineIdentifier >> 8;
    client->send_buf[3] = routineIdentifier;
    if (size) {
        if (NULL == data) {
            return UDS_ERR_INVALID_ARG;
        }
        if (size > client->send_buf_size - UDS_0X31_REQ_MIN_LEN) {
            return UDS_ERR_BUFSIZ;
        }
        memmove(&client->send_buf[UDS_0X31_REQ_MIN_LEN], data, size);
    } else {
        if (NULL != data) {
            UDS_LOGI(__FILE__, "warning: size zero and data non-null");
        }
    }
    client->send_size = UDS_0X31_REQ_MIN_LEN + size;
    return SendRequest(client);
}

/**
 * @brief
 *
 * @param client
 * @param dataFormatIdentifier
 * @param addressAndLengthFormatIdentifier
 * @param memoryAddress
 * @param memorySize
 * @return UDSErr_t
 * @addtogroup requestDownload_0x34
 */
UDSErr_t UDSSendRequestDownload(UDSClient_t *client, uint8_t dataFormatIdentifier,
                                uint8_t addressAndLengthFormatIdentifier, size_t memoryAddress,
                                size_t memorySize) {
    UDSErr_t err = PreRequestCheck(client);
    if (err) {
        return err;
    }
    uint8_t numMemorySizeBytes = (addressAndLengthFormatIdentifier & 0xF0) >> 4;
    uint8_t numMemoryAddressBytes = addressAndLengthFormatIdentifier & 0x0F;

    client->send_buf[0] = kSID_REQUEST_DOWNLOAD;
    client->send_buf[1] = dataFormatIdentifier;
    client->send_buf[2] = addressAndLengthFormatIdentifier;

    uint8_t *ptr = &client->send_buf[UDS_0X34_REQ_BASE_LEN];

    for (int i = numMemoryAddressBytes - 1; i >= 0; i--) {
        *ptr = (memoryAddress & (0xFF << (8 * i))) >> (8 * i);
        ptr++;
    }

    for (int i = numMemorySizeBytes - 1; i >= 0; i--) {
        *ptr = (memorySize & (0xFF << (8 * i))) >> (8 * i);
        ptr++;
    }

    client->send_size = UDS_0X34_REQ_BASE_LEN + numMemoryAddressBytes + numMemorySizeBytes;
    return SendRequest(client);
}

/**
 * @brief
 *
 * @param client
 * @param dataFormatIdentifier
 * @param addressAndLengthFormatIdentifier
 * @param memoryAddress
 * @param memorySize
 * @return UDSErr_t
 * @addtogroup requestDownload_0x35
 */
UDSErr_t UDSSendRequestUpload(UDSClient_t *client, uint8_t dataFormatIdentifier,
                              uint8_t addressAndLengthFormatIdentifier, size_t memoryAddress,
                              size_t memorySize) {
    UDSErr_t err = PreRequestCheck(client);
    if (err) {
        return err;
    }
    uint8_t numMemorySizeBytes = (addressAndLengthFormatIdentifier & 0xF0) >> 4;
    uint8_t numMemoryAddressBytes = addressAndLengthFormatIdentifier & 0x0F;

    client->send_buf[0] = kSID_REQUEST_UPLOAD;
    client->send_buf[1] = dataFormatIdentifier;
    client->send_buf[2] = addressAndLengthFormatIdentifier;

    uint8_t *ptr = &client->send_buf[UDS_0X35_REQ_BASE_LEN];

    for (int i = numMemoryAddressBytes - 1; i >= 0; i--) {
        *ptr = (memoryAddress & (0xFF << (8 * i))) >> (8 * i);
        ptr++;
    }

    for (int i = numMemorySizeBytes - 1; i >= 0; i--) {
        *ptr = (memorySize & (0xFF << (8 * i))) >> (8 * i);
        ptr++;
    }

    client->send_size = UDS_0X35_REQ_BASE_LEN + numMemoryAddressBytes + numMemorySizeBytes;
    return SendRequest(client);
}

/**
 * @brief
 *
 * @param client
 * @param blockSequenceCounter
 * @param blockLength
 * @param fd
 * @return UDSErr_t
 * @addtogroup transferData_0x36
 */
UDSErr_t UDSSendTransferData(UDSClient_t *client, uint8_t blockSequenceCounter,
                             const uint16_t blockLength, const uint8_t *data, uint16_t size) {
    UDSErr_t err = PreRequestCheck(client);
    if (err) {
        return err;
    }

    // blockLength must include SID and sequenceCounter
    if (blockLength <= 2) {
        return UDS_ERR_INVALID_ARG;
    }

    // data must fit inside blockLength - 2
    if (size > (blockLength - 2)) {
        return UDS_ERR_INVALID_ARG;
    }
    client->send_buf[0] = kSID_TRANSFER_DATA;
    client->send_buf[1] = blockSequenceCounter;
    memmove(&client->send_buf[UDS_0X36_REQ_BASE_LEN], data, size);
    UDS_LOGI(__FILE__, "size: %d, blocklength: %d", size, blockLength);
    client->send_size = UDS_0X36_REQ_BASE_LEN + size;
    return SendRequest(client);
}

UDSErr_t UDSSendTransferDataStream(UDSClient_t *client, uint8_t blockSequenceCounter,
                                   const uint16_t blockLength, FILE *fd) {
    UDSErr_t err = PreRequestCheck(client);
    if (err) {
        return err;
    }
    // blockLength must include SID and sequenceCounter
    if (blockLength <= 2) {
        return UDS_ERR_INVALID_ARG;
    }
    client->send_buf[0] = kSID_TRANSFER_DATA;
    client->send_buf[1] = blockSequenceCounter;

    uint16_t size = fread(&client->send_buf[2], 1, blockLength - 2, fd);
    UDS_LOGI(__FILE__, "size: %d, blocklength: %d", size, blockLength);
    client->send_size = UDS_0X36_REQ_BASE_LEN + size;
    return SendRequest(client);
}

/**
 * @brief
 *
 * @param client
 * @return UDSErr_t
 * @addtogroup requestTransferExit_0x37
 */
UDSErr_t UDSSendRequestTransferExit(UDSClient_t *client) {
    UDSErr_t err = PreRequestCheck(client);
    if (err) {
        return err;
    }
    client->send_buf[0] = kSID_REQUEST_TRANSFER_EXIT;
    client->send_size = 1;
    return SendRequest(client);
}

UDSErr_t UDSSendRequestFileTransfer(UDSClient_t *client, enum FileOperationMode mode,
                                    const char *filePath, uint8_t dataFormatIdentifier,
                                    uint8_t fileSizeParameterLength, size_t fileSizeUncompressed,
                                    size_t fileSizeCompressed) {
    UDSErr_t err = PreRequestCheck(client);
    if (err) {
        return err;
    }
    uint16_t filePathLen = strlen(filePath);
    if (filePathLen < 1)
        return UDS_FAIL;

    uint8_t fileSizeBytes = 0;
    if ((mode == kAddFile) || (mode == kReplaceFile)) {
        fileSizeBytes = fileSizeParameterLength;
    }
    size_t bufSize = 5 + filePathLen + fileSizeBytes + fileSizeBytes;
    if ((mode == kAddFile) || (mode == kReplaceFile) || (mode == kReadFile)) {
        bufSize += 1;
    }
    if (client->send_buf_size < bufSize)
        return UDS_ERR_BUFSIZ;

    client->send_buf[0] = kSID_REQUEST_FILE_TRANSFER;
    client->send_buf[1] = mode;
    client->send_buf[2] = (filePathLen >> 8) & 0xFF;
    client->send_buf[3] = filePathLen & 0xFF;
    memcpy(&client->send_buf[4], filePath, filePathLen);
    if ((mode == kAddFile) || (mode == kReplaceFile) || (mode == kReadFile)) {
        client->send_buf[4 + filePathLen] = dataFormatIdentifier;
    }
    if ((mode == kAddFile) || (mode == kReplaceFile)) {
        client->send_buf[5 + filePathLen] = fileSizeParameterLength;
        uint8_t *ptr = &client->send_buf[6 + filePathLen];
        for (int i = fileSizeParameterLength - 1; i >= 0; i--) {
            *ptr = (fileSizeUncompressed & (0xFF << (8 * i))) >> (8 * i);
            ptr++;
        }

        for (int i = fileSizeParameterLength - 1; i >= 0; i--) {
            *ptr = (fileSizeCompressed & (0xFF << (8 * i))) >> (8 * i);
            ptr++;
        }
    }

    client->send_size = bufSize;
    return SendRequest(client);
}

/**
 * @brief
 *
 * @param client
 * @param dtcSettingType
 * @param data
 * @param size
 * @return UDSErr_t
 * @addtogroup controlDTCSetting_0x85
 */
UDSErr_t UDSCtrlDTCSetting(UDSClient_t *client, uint8_t dtcSettingType, uint8_t *data,
                           uint16_t size) {
    UDSErr_t err = PreRequestCheck(client);
    if (err) {
        return err;
    }

    // these are reserved values
    if (0x00 == dtcSettingType || 0x7F == dtcSettingType ||
        (0x03 <= dtcSettingType && dtcSettingType <= 0x3F)) {
        return UDS_ERR_INVALID_ARG;
    }

    client->send_buf[0] = kSID_CONTROL_DTC_SETTING;
    client->send_buf[1] = dtcSettingType;

    if (NULL == data) {
        if (size != 0) {
            return UDS_ERR_INVALID_ARG;
        }
    } else {
        if (size == 0) {
            UDS_LOGI(__FILE__, "warning: size == 0 and data is non-null");
        }
        if (size > client->send_buf_size - 2) {
            return UDS_ERR_BUFSIZ;
        }
        memmove(&client->send_buf[2], data, size);
    }
    client->send_size = 2 + size;
    return SendRequest(client);
}

/**
 * @brief
 *
 * @param client
 * @param level
 * @param data
 * @param size
 * @return UDSErr_t
 * @addtogroup securityAccess_0x27
 */
UDSErr_t UDSSendSecurityAccess(UDSClient_t *client, uint8_t level, uint8_t *data, uint16_t size) {
    UDSErr_t err = PreRequestCheck(client);
    if (err) {
        return err;
    }
    if (UDSSecurityAccessLevelIsReserved(level)) {
        return UDS_ERR_INVALID_ARG;
    }
    client->send_buf[0] = kSID_SECURITY_ACCESS;
    client->send_buf[1] = level;
    if (size) {
        if (NULL == data) {
            return UDS_ERR_INVALID_ARG;
        }
        if (size > client->send_buf_size - UDS_0X27_REQ_BASE_LEN) {
            return UDS_ERR_BUFSIZ;
        }
    } else {
        if (NULL != data) {
            UDS_LOGI(__FILE__, "warning: size == 0 and data is non-null");
        }
    }

    memmove(&client->send_buf[UDS_0X27_REQ_BASE_LEN], data, size);
    client->send_size = UDS_0X27_REQ_BASE_LEN + size;
    return SendRequest(client);
}

/**
 * @brief
 *
 * @param client
 * @param resp
 * @return UDSErr_t
 * @addtogroup securityAccess_0x27
 */
UDSErr_t UDSUnpackSecurityAccessResponse(const UDSClient_t *client,
                                         struct SecurityAccessResponse *resp) {
    if (NULL == client || NULL == resp) {
        return UDS_ERR_INVALID_ARG;
    }
    if (UDS_RESPONSE_SID_OF(kSID_SECURITY_ACCESS) != client->recv_buf[0]) {
        return UDS_ERR_SID_MISMATCH;
    }
    if (client->recv_size < UDS_0X27_RESP_BASE_LEN) {
        return UDS_ERR_RESP_TOO_SHORT;
    }
    resp->securityAccessType = client->recv_buf[1];
    resp->securitySeedLength = client->recv_size - UDS_0X27_RESP_BASE_LEN;
    resp->securitySeed = resp->securitySeedLength == 0 ? NULL : &client->recv_buf[2];
    return UDS_OK;
}

/**
 * @brief
 *
 * @param client
 * @param resp
 * @return UDSErr_t
 * @addtogroup routineControl_0x31
 */
UDSErr_t UDSUnpackRoutineControlResponse(const UDSClient_t *client,
                                         struct RoutineControlResponse *resp) {
    if (NULL == client || NULL == resp) {
        return UDS_ERR_INVALID_ARG;
    }
    if (UDS_RESPONSE_SID_OF(kSID_ROUTINE_CONTROL) != client->recv_buf[0]) {
        return UDS_ERR_SID_MISMATCH;
    }
    if (client->recv_size < UDS_0X31_RESP_MIN_LEN) {
        return UDS_ERR_RESP_TOO_SHORT;
    }
    resp->routineControlType = client->recv_buf[1];
    resp->routineIdentifier = (client->recv_buf[2] << 8) + client->recv_buf[3];
    resp->routineStatusRecordLength = client->recv_size - UDS_0X31_RESP_MIN_LEN;
    resp->routineStatusRecord =
        resp->routineStatusRecordLength == 0 ? NULL : &client->recv_buf[UDS_0X31_RESP_MIN_LEN];
    return UDS_OK;
}

/**
 * @brief
 *
 * @param client
 * @param resp
 * @return UDSErr_t
 * @addtogroup requestDownload_0x34
 */
UDSErr_t UDSUnpackRequestDownloadResponse(const UDSClient_t *client,
                                          struct RequestDownloadResponse *resp) {
    if (NULL == client || NULL == resp) {
        return UDS_ERR_INVALID_ARG;
    }
    if (UDS_RESPONSE_SID_OF(kSID_REQUEST_DOWNLOAD) != client->recv_buf[0]) {
        return UDS_ERR_SID_MISMATCH;
    }
    if (client->recv_size < UDS_0X34_RESP_BASE_LEN) {
        return UDS_ERR_RESP_TOO_SHORT;
    }
    uint8_t maxNumberOfBlockLengthSize = (client->recv_buf[1] & 0xF0) >> 4;

    if (sizeof(resp->maxNumberOfBlockLength) < maxNumberOfBlockLengthSize) {
        UDS_LOGI(__FILE__, "WARNING: sizeof(maxNumberOfBlockLength) > sizeof(size_t)");
        return UDS_FAIL;
    }
    resp->maxNumberOfBlockLength = 0;
    for (int byteIdx = 0; byteIdx < maxNumberOfBlockLengthSize; byteIdx++) {
        uint8_t byte = client->recv_buf[UDS_0X34_RESP_BASE_LEN + byteIdx];
        uint8_t shiftBytes = maxNumberOfBlockLengthSize - 1 - byteIdx;
        resp->maxNumberOfBlockLength |= byte << (8 * shiftBytes);
    }
    return UDS_OK;
}

UDSErr_t UDSClientPoll(UDSClient_t *client) {
    if (NULL == client->fn) {
        return UDS_ERR_MISUSE;
    }

    UDSErr_t err = PollLowLevel(client);
    switch (err) {
    case UDS_OK:
    case UDS_NRC_RequestCorrectlyReceived_ResponsePending:
        break;
    default:
        client->fn(client, UDS_EVT_Err, &err);
        changeState(client, kRequestStateIdle);
        break;
    }
    client->fn(client, UDS_EVT_Poll, NULL);
    return err;
}

UDSErr_t UDSUnpackRDBIResponse(UDSClient_t *client, UDSRDBIVar_t *vars, uint16_t numVars) {
    uint16_t offset = UDS_0X22_RESP_BASE_LEN;
    if (client == NULL || vars == NULL) {
        return UDS_ERR_INVALID_ARG;
    }
    for (int i = 0; i < numVars; i++) {

        if (offset + sizeof(uint16_t) > client->recv_size) {
            return UDS_ERR_RESP_TOO_SHORT;
        }
        uint16_t did = (client->recv_buf[offset] << 8) + client->recv_buf[offset + 1];
        if (did != vars[i].did) {
            return UDS_ERR_DID_MISMATCH;
        }
        if (offset + sizeof(uint16_t) + vars[i].len > client->recv_size) {
            return UDS_ERR_RESP_TOO_SHORT;
        }
        if (vars[i].UnpackFn) {
            vars[i].UnpackFn(vars[i].data, client->recv_buf + offset + sizeof(uint16_t),
                             vars[i].len);
        } else {
            return UDS_ERR_INVALID_ARG;
        }
        offset += sizeof(uint16_t) + vars[i].len;
    }
    return UDS_OK;
}


#ifdef UDS_LINES
#line 1 "src/server.c"
#endif





static inline uint8_t NegativeResponse(UDSReq_t *r, uint8_t response_code) {
    r->send_buf[0] = 0x7F;
    r->send_buf[1] = r->recv_buf[0];
    r->send_buf[2] = response_code;
    r->send_len = UDS_NEG_RESP_LEN;
    return response_code;
}

static inline void NoResponse(UDSReq_t *r) { r->send_len = 0; }

static uint8_t EmitEvent(UDSServer_t *srv, UDSEvent_t evt, void *data) {
    if (srv->fn) {
        return srv->fn(srv, evt, data);
    } else {
        UDS_LOGI(__FILE__, "Unhandled UDSEvent %d, srv.fn not installed!\n", evt);
        return UDS_NRC_GeneralReject;
    }
}

static uint8_t _0x10_DiagnosticSessionControl(UDSServer_t *srv, UDSReq_t *r) {
    if (r->recv_len < UDS_0X10_REQ_LEN) {
        return NegativeResponse(r, UDS_NRC_IncorrectMessageLengthOrInvalidFormat);
    }

    uint8_t sessType = r->recv_buf[1] & 0x4F;

    UDSDiagSessCtrlArgs_t args = {
        .type = sessType,
        .p2_ms = UDS_CLIENT_DEFAULT_P2_MS,
        .p2_star_ms = UDS_CLIENT_DEFAULT_P2_STAR_MS,
    };

    uint8_t err = EmitEvent(srv, UDS_EVT_DiagSessCtrl, &args);

    if (UDS_PositiveResponse != err) {
        return NegativeResponse(r, err);
    }

    srv->sessionType = sessType;

    switch (sessType) {
    case kDefaultSession:
        break;
    case kProgrammingSession:
    case kExtendedDiagnostic:
    default:
        srv->s3_session_timeout_timer = UDSMillis() + srv->s3_ms;
        break;
    }

    r->send_buf[0] = UDS_RESPONSE_SID_OF(kSID_DIAGNOSTIC_SESSION_CONTROL);
    r->send_buf[1] = sessType;

    // UDS-1-2013: Table 29
    // resolution: 1ms
    r->send_buf[2] = args.p2_ms >> 8;
    r->send_buf[3] = args.p2_ms;

    // resolution: 10ms
    r->send_buf[4] = (args.p2_star_ms / 10) >> 8;
    r->send_buf[5] = args.p2_star_ms / 10;

    r->send_len = UDS_0X10_RESP_LEN;
    return UDS_PositiveResponse;
}

static uint8_t _0x11_ECUReset(UDSServer_t *srv, UDSReq_t *r) {
    uint8_t resetType = r->recv_buf[1] & 0x3F;

    if (r->recv_len < UDS_0X11_REQ_MIN_LEN) {
        return NegativeResponse(r, UDS_NRC_IncorrectMessageLengthOrInvalidFormat);
    }

    UDSECUResetArgs_t args = {
        .type = resetType,
        .powerDownTimeMillis = UDS_SERVER_DEFAULT_POWER_DOWN_TIME_MS,
    };

    uint8_t err = EmitEvent(srv, UDS_EVT_EcuReset, &args);

    if (UDS_PositiveResponse == err) {
        srv->notReadyToReceive = true;
        srv->ecuResetScheduled = resetType;
        srv->ecuResetTimer = UDSMillis() + args.powerDownTimeMillis;
    } else {
        return NegativeResponse(r, err);
    }

    r->send_buf[0] = UDS_RESPONSE_SID_OF(kSID_ECU_RESET);
    r->send_buf[1] = resetType;

    if (kEnableRapidPowerShutDown == resetType) {
        uint32_t powerDownTime = args.powerDownTimeMillis / 1000;
        if (powerDownTime > 255) {
            powerDownTime = 255;
        }
        r->send_buf[2] = powerDownTime;
        r->send_len = UDS_0X11_RESP_BASE_LEN + 1;
    } else {
        r->send_len = UDS_0X11_RESP_BASE_LEN;
    }
    return UDS_PositiveResponse;
}

static uint8_t safe_copy(UDSServer_t *srv, const void *src, uint16_t count) {
    if (srv == NULL) {
        return UDS_NRC_GeneralReject;
    }
    UDSReq_t *r = (UDSReq_t *)&srv->r;
    if (count <= r->send_buf_size - r->send_len) {
        memmove(r->send_buf + r->send_len, src, count);
        r->send_len += count;
        return UDS_PositiveResponse;
    }
    return UDS_NRC_ResponseTooLong;
}

static uint8_t _0x22_ReadDataByIdentifier(UDSServer_t *srv, UDSReq_t *r) {
    uint8_t numDIDs;
    uint16_t dataId = 0;
    uint8_t ret = UDS_PositiveResponse;
    r->send_buf[0] = UDS_RESPONSE_SID_OF(kSID_READ_DATA_BY_IDENTIFIER);
    r->send_len = 1;

    if (0 != (r->recv_len - 1) % sizeof(uint16_t)) {
        return NegativeResponse(r, UDS_NRC_IncorrectMessageLengthOrInvalidFormat);
    }

    numDIDs = r->recv_len / sizeof(uint16_t);

    if (0 == numDIDs) {
        return NegativeResponse(r, UDS_NRC_IncorrectMessageLengthOrInvalidFormat);
    }

    for (int did = 0; did < numDIDs; did++) {
        uint16_t idx = 1 + did * 2;
        dataId = (r->recv_buf[idx] << 8) + r->recv_buf[idx + 1];

        if (r->send_len + 3 > r->send_buf_size) {
            return NegativeResponse(r, UDS_NRC_ResponseTooLong);
        }
        uint8_t *copylocation = r->send_buf + r->send_len;
        copylocation[0] = dataId >> 8;
        copylocation[1] = dataId;
        r->send_len += 2;

        UDSRDBIArgs_t args = {
            .dataId = dataId,
            .copy = safe_copy,
        };

        unsigned send_len_before = r->send_len;
        ret = EmitEvent(srv, UDS_EVT_ReadDataByIdent, &args);
        if (ret == UDS_PositiveResponse && send_len_before == r->send_len) {
            UDS_LOGI(__FILE__, "ERROR: RDBI response positive but no data sent\n");
            return NegativeResponse(r, UDS_NRC_GeneralReject);
        }

        if (UDS_PositiveResponse != ret) {
            return NegativeResponse(r, ret);
        }
    }
    return UDS_PositiveResponse;
}

/**
 * @brief decode the addressAndLengthFormatIdentifier that appears in ReadMemoryByAddress (0x23),
 * DynamicallyDefineDataIdentifier (0x2C), RequestDownload (0X34)
 *
 * @param srv
 * @param buf pointer to addressAndDataLengthFormatIdentifier in recv_buf
 * @param memoryAddress the decoded memory address
 * @param memorySize the decoded memory size
 * @return uint8_t
 */
static uint8_t decodeAddressAndLength(UDSReq_t *r, uint8_t *const buf, void **memoryAddress,
                                      size_t *memorySize) {
    UDS_ASSERT(r);
    UDS_ASSERT(memoryAddress);
    UDS_ASSERT(memorySize);
    uintptr_t tmp = 0;
    *memoryAddress = 0;
    *memorySize = 0;

    UDS_ASSERT(buf >= r->recv_buf && buf <= r->recv_buf + sizeof(r->recv_buf));

    if (r->recv_len < 3) {
        return NegativeResponse(r, UDS_NRC_IncorrectMessageLengthOrInvalidFormat);
    }

    uint8_t memorySizeLength = (buf[0] & 0xF0) >> 4;
    uint8_t memoryAddressLength = buf[0] & 0x0F;

    if (memorySizeLength == 0 || memorySizeLength > sizeof(size_t)) {
        return NegativeResponse(r, UDS_NRC_RequestOutOfRange);
    }

    if (memoryAddressLength == 0 || memoryAddressLength > sizeof(size_t)) {
        return NegativeResponse(r, UDS_NRC_RequestOutOfRange);
    }

    if (buf + memorySizeLength + memoryAddressLength > r->recv_buf + r->recv_len) {
        return NegativeResponse(r, UDS_NRC_IncorrectMessageLengthOrInvalidFormat);
    }

    for (int byteIdx = 0; byteIdx < memoryAddressLength; byteIdx++) {
        long long unsigned int byte = buf[1 + byteIdx];
        uint8_t shiftBytes = memoryAddressLength - 1 - byteIdx;
        tmp |= byte << (8 * shiftBytes);
    }
    *memoryAddress = (void *)tmp;

    for (int byteIdx = 0; byteIdx < memorySizeLength; byteIdx++) {
        uint8_t byte = buf[1 + memoryAddressLength + byteIdx];
        uint8_t shiftBytes = memorySizeLength - 1 - byteIdx;
        *memorySize |= (size_t)byte << (8 * shiftBytes);
    }
    return UDS_PositiveResponse;
}

static uint8_t _0x23_ReadMemoryByAddress(UDSServer_t *srv, UDSReq_t *r) {
    uint8_t ret = UDS_PositiveResponse;
    void *address = 0;
    size_t length = 0;

    if (r->recv_len < UDS_0X23_REQ_MIN_LEN) {
        return NegativeResponse(r, UDS_NRC_IncorrectMessageLengthOrInvalidFormat);
    }

    ret = decodeAddressAndLength(r, &r->recv_buf[1], &address, &length);
    if (UDS_PositiveResponse != ret) {
        return NegativeResponse(r, ret);
    }

    UDSReadMemByAddrArgs_t args = {
        .memAddr = address,
        .memSize = length,
        .copy = safe_copy,
    };

    r->send_buf[0] = UDS_RESPONSE_SID_OF(kSID_READ_MEMORY_BY_ADDRESS);
    r->send_len = UDS_0X23_RESP_BASE_LEN;
    ret = EmitEvent(srv, UDS_EVT_ReadMemByAddr, &args);
    if (UDS_PositiveResponse != ret) {
        return NegativeResponse(r, ret);
    }
    if (r->send_len != UDS_0X23_RESP_BASE_LEN + length) {
        return UDS_NRC_GeneralProgrammingFailure;
    }
    return UDS_PositiveResponse;
}

static uint8_t _0x27_SecurityAccess(UDSServer_t *srv, UDSReq_t *r) {
    uint8_t subFunction = r->recv_buf[1];
    uint8_t response = UDS_PositiveResponse;

    if (UDSSecurityAccessLevelIsReserved(subFunction)) {
        return NegativeResponse(r, UDS_NRC_IncorrectMessageLengthOrInvalidFormat);
    }

    if (!UDSTimeAfter(UDSMillis(), srv->sec_access_boot_delay_timer)) {
        return NegativeResponse(r, UDS_NRC_RequiredTimeDelayNotExpired);
    }

    if (!(UDSTimeAfter(UDSMillis(), srv->sec_access_auth_fail_timer))) {
        return NegativeResponse(r, UDS_NRC_ExceedNumberOfAttempts);
    }

    r->send_buf[0] = UDS_RESPONSE_SID_OF(kSID_SECURITY_ACCESS);
    r->send_buf[1] = subFunction;
    r->send_len = UDS_0X27_RESP_BASE_LEN;

    // Even: sendKey
    if (0 == subFunction % 2) {
        uint8_t requestedLevel = subFunction - 1;
        UDSSecAccessValidateKeyArgs_t args = {
            .level = requestedLevel,
            .key = &r->recv_buf[UDS_0X27_REQ_BASE_LEN],
            .len = r->recv_len - UDS_0X27_REQ_BASE_LEN,
        };

        response = EmitEvent(srv, UDS_EVT_SecAccessValidateKey, &args);

        if (UDS_PositiveResponse != response) {
            srv->sec_access_auth_fail_timer =
                UDSMillis() + UDS_SERVER_0x27_BRUTE_FORCE_MITIGATION_AUTH_FAIL_DELAY_MS;
            return NegativeResponse(r, response);
        }

        // "requestSeed = 0x01" identifies a fixed relationship between
        // "requestSeed = 0x01" and "sendKey = 0x02"
        // "requestSeed = 0x03" identifies a fixed relationship between
        // "requestSeed = 0x03" and "sendKey = 0x04"
        srv->securityLevel = requestedLevel;
        r->send_len = UDS_0X27_RESP_BASE_LEN;
        return UDS_PositiveResponse;
    }

    // Odd: requestSeed
    else {
        /* If a server supports security, but the requested security level is already unlocked when
        a SecurityAccess ‘requestSeed’ message is received, that server shall respond with a
        SecurityAccess ‘requestSeed’ positive response message service with a seed value equal to
        zero (0). The server shall never send an all zero seed for a given security level that is
        currently locked. The client shall use this method to determine if a server is locked for a
        particular security level by checking for a non-zero seed.
        */
        if (subFunction == srv->securityLevel) {
            // Table 52 sends a response of length 2. Use a preprocessor define if this needs
            // customizing by the user.
            const uint8_t already_unlocked[] = {0x00, 0x00};
            return safe_copy(srv, already_unlocked, sizeof(already_unlocked));
        } else {
            UDSSecAccessRequestSeedArgs_t args = {
                .level = subFunction,
                .dataRecord = &r->recv_buf[UDS_0X27_REQ_BASE_LEN],
                .len = r->recv_len - UDS_0X27_REQ_BASE_LEN,
                .copySeed = safe_copy,
            };

            response = EmitEvent(srv, UDS_EVT_SecAccessRequestSeed, &args);

            if (UDS_PositiveResponse != response) {
                return NegativeResponse(r, response);
            }

            if (r->send_len <= UDS_0X27_RESP_BASE_LEN) { // no data was copied
                return NegativeResponse(r, UDS_NRC_GeneralProgrammingFailure);
            }
            return UDS_PositiveResponse;
        }
    }
    return NegativeResponse(r, UDS_NRC_GeneralProgrammingFailure);
}

static uint8_t _0x28_CommunicationControl(UDSServer_t *srv, UDSReq_t *r) {
    uint8_t controlType = r->recv_buf[1] & 0x7F;
    uint8_t communicationType = r->recv_buf[2];

    if (r->recv_len < UDS_0X28_REQ_BASE_LEN) {
        return NegativeResponse(r, UDS_NRC_IncorrectMessageLengthOrInvalidFormat);
    }

    UDSCommCtrlArgs_t args = {
        .ctrlType = controlType,
        .commType = communicationType,
    };

    uint8_t err = EmitEvent(srv, UDS_EVT_CommCtrl, &args);
    if (UDS_PositiveResponse != err) {
        return NegativeResponse(r, err);
    }

    r->send_buf[0] = UDS_RESPONSE_SID_OF(kSID_COMMUNICATION_CONTROL);
    r->send_buf[1] = controlType;
    r->send_len = UDS_0X28_RESP_LEN;
    return UDS_PositiveResponse;
}

static uint8_t _0x2E_WriteDataByIdentifier(UDSServer_t *srv, UDSReq_t *r) {
    uint16_t dataLen = 0;
    uint16_t dataId = 0;
    uint8_t err = UDS_PositiveResponse;

    /* UDS-1 2013 Figure 21 Key 1 */
    if (r->recv_len < UDS_0X2E_REQ_MIN_LEN) {
        return NegativeResponse(r, UDS_NRC_IncorrectMessageLengthOrInvalidFormat);
    }

    dataId = (r->recv_buf[1] << 8) + r->recv_buf[2];
    dataLen = r->recv_len - UDS_0X2E_REQ_BASE_LEN;

    UDSWDBIArgs_t args = {
        .dataId = dataId,
        .data = &r->recv_buf[UDS_0X2E_REQ_BASE_LEN],
        .len = dataLen,
    };

    err = EmitEvent(srv, UDS_EVT_WriteDataByIdent, &args);
    if (UDS_PositiveResponse != err) {
        return NegativeResponse(r, err);
    }

    r->send_buf[0] = UDS_RESPONSE_SID_OF(kSID_WRITE_DATA_BY_IDENTIFIER);
    r->send_buf[1] = dataId >> 8;
    r->send_buf[2] = dataId;
    r->send_len = UDS_0X2E_RESP_LEN;
    return UDS_PositiveResponse;
}

static uint8_t _0x31_RoutineControl(UDSServer_t *srv, UDSReq_t *r) {
    uint8_t err = UDS_PositiveResponse;
    if (r->recv_len < UDS_0X31_REQ_MIN_LEN) {
        return NegativeResponse(r, UDS_NRC_IncorrectMessageLengthOrInvalidFormat);
    }

    uint8_t routineControlType = r->recv_buf[1] & 0x7F;
    uint16_t routineIdentifier = (r->recv_buf[2] << 8) + r->recv_buf[3];

    UDSRoutineCtrlArgs_t args = {
        .ctrlType = routineControlType,
        .id = routineIdentifier,
        .optionRecord = &r->recv_buf[UDS_0X31_REQ_MIN_LEN],
        .len = r->recv_len - UDS_0X31_REQ_MIN_LEN,
        .copyStatusRecord = safe_copy,
    };

    r->send_buf[0] = UDS_RESPONSE_SID_OF(kSID_ROUTINE_CONTROL);
    r->send_buf[1] = routineControlType;
    r->send_buf[2] = routineIdentifier >> 8;
    r->send_buf[3] = routineIdentifier;
    r->send_len = UDS_0X31_RESP_MIN_LEN;

    switch (routineControlType) {
    case kStartRoutine:
    case kStopRoutine:
    case kRequestRoutineResults:
        err = EmitEvent(srv, UDS_EVT_RoutineCtrl, &args);
        if (UDS_PositiveResponse != err) {
            return NegativeResponse(r, err);
        }
        break;
    default:
        return NegativeResponse(r, UDS_NRC_RequestOutOfRange);
    }
    return UDS_PositiveResponse;
}

static void ResetTransfer(UDSServer_t *srv) {
    UDS_ASSERT(srv);
    srv->xferBlockSequenceCounter = 1;
    srv->xferByteCounter = 0;
    srv->xferTotalBytes = 0;
    srv->xferIsActive = false;
}

static uint8_t _0x34_RequestDownload(UDSServer_t *srv, UDSReq_t *r) {
    uint8_t err;
    void *memoryAddress = 0;
    size_t memorySize = 0;

    if (srv->xferIsActive) {
        return NegativeResponse(r, UDS_NRC_ConditionsNotCorrect);
    }

    if (r->recv_len < UDS_0X34_REQ_BASE_LEN) {
        return NegativeResponse(r, UDS_NRC_IncorrectMessageLengthOrInvalidFormat);
    }

    err = decodeAddressAndLength(r, &r->recv_buf[2], &memoryAddress, &memorySize);
    if (UDS_PositiveResponse != err) {
        return NegativeResponse(r, err);
    }

    UDSRequestDownloadArgs_t args = {
        .addr = memoryAddress,
        .size = memorySize,
        .dataFormatIdentifier = r->recv_buf[1],
        .maxNumberOfBlockLength = UDS_SERVER_DEFAULT_XFER_DATA_MAX_BLOCKLENGTH,
    };

    err = EmitEvent(srv, UDS_EVT_RequestDownload, &args);

    if (args.maxNumberOfBlockLength < 3) {
        UDS_LOGI(__FILE__, "ERROR: maxNumberOfBlockLength too short");
        return NegativeResponse(r, UDS_NRC_GeneralProgrammingFailure);
    }

    if (UDS_PositiveResponse != err) {
        return NegativeResponse(r, err);
    }

    ResetTransfer(srv);
    srv->xferIsActive = true;
    srv->xferTotalBytes = memorySize;
    srv->xferBlockLength = args.maxNumberOfBlockLength;

    // ISO-14229-1:2013 Table 401:
    uint8_t lengthFormatIdentifier = sizeof(args.maxNumberOfBlockLength) << 4;

    /* ISO-14229-1:2013 Table 396: maxNumberOfBlockLength
    This parameter is used by the requestDownload positive response message to
    inform the client how many data bytes (maxNumberOfBlockLength) to include in
    each TransferData request message from the client. This length reflects the
    complete message length, including the service identifier and the
    data-parameters present in the TransferData request message.
    */
    if (args.maxNumberOfBlockLength > UDS_TP_MTU) {
        args.maxNumberOfBlockLength = UDS_TP_MTU;
    }

    r->send_buf[0] = UDS_RESPONSE_SID_OF(kSID_REQUEST_DOWNLOAD);
    r->send_buf[1] = lengthFormatIdentifier;
    for (uint8_t idx = 0; idx < sizeof(args.maxNumberOfBlockLength); idx++) {
        uint8_t shiftBytes = sizeof(args.maxNumberOfBlockLength) - 1 - idx;
        uint8_t byte = args.maxNumberOfBlockLength >> (shiftBytes * 8);
        r->send_buf[UDS_0X34_RESP_BASE_LEN + idx] = byte;
    }
    r->send_len = UDS_0X34_RESP_BASE_LEN + sizeof(args.maxNumberOfBlockLength);
    return UDS_PositiveResponse;
}

static uint8_t _0x35_RequestUpload(UDSServer_t *srv, UDSReq_t *r) {
    uint8_t err;
    void *memoryAddress = 0;
    size_t memorySize = 0;

    if (srv->xferIsActive) {
        return NegativeResponse(r, UDS_NRC_ConditionsNotCorrect);
    }

    if (r->recv_len < UDS_0X35_REQ_BASE_LEN) {
        return NegativeResponse(r, UDS_NRC_IncorrectMessageLengthOrInvalidFormat);
    }

    err = decodeAddressAndLength(r, &r->recv_buf[2], &memoryAddress, &memorySize);
    if (UDS_PositiveResponse != err) {
        return NegativeResponse(r, err);
    }

    UDSRequestUploadArgs_t args = {
        .addr = memoryAddress,
        .size = memorySize,
        .dataFormatIdentifier = r->recv_buf[1],
        .maxNumberOfBlockLength = UDS_SERVER_DEFAULT_XFER_DATA_MAX_BLOCKLENGTH,
    };

    err = EmitEvent(srv, UDS_EVT_RequestUpload, &args);

    if (args.maxNumberOfBlockLength < 3) {
        UDS_LOGI(__FILE__, "ERROR: maxNumberOfBlockLength too short");
        return NegativeResponse(r, UDS_NRC_GeneralProgrammingFailure);
    }

    if (UDS_PositiveResponse != err) {
        return NegativeResponse(r, err);
    }

    ResetTransfer(srv);
    srv->xferIsActive = true;
    srv->xferTotalBytes = memorySize;
    srv->xferBlockLength = args.maxNumberOfBlockLength;

    uint8_t lengthFormatIdentifier = sizeof(args.maxNumberOfBlockLength) << 4;

    r->send_buf[0] = UDS_RESPONSE_SID_OF(kSID_REQUEST_UPLOAD);
    r->send_buf[1] = lengthFormatIdentifier;
    for (uint8_t idx = 0; idx < sizeof(args.maxNumberOfBlockLength); idx++) {
        uint8_t shiftBytes = sizeof(args.maxNumberOfBlockLength) - 1 - idx;
        uint8_t byte = args.maxNumberOfBlockLength >> (shiftBytes * 8);
        r->send_buf[UDS_0X35_RESP_BASE_LEN + idx] = byte;
    }
    r->send_len = UDS_0X35_RESP_BASE_LEN + sizeof(args.maxNumberOfBlockLength);
    return UDS_PositiveResponse;
}

static uint8_t _0x36_TransferData(UDSServer_t *srv, UDSReq_t *r) {
    uint8_t err = UDS_PositiveResponse;
    uint16_t request_data_len = r->recv_len - UDS_0X36_REQ_BASE_LEN;
    uint8_t blockSequenceCounter = 0;

    if (!srv->xferIsActive) {
        return NegativeResponse(r, UDS_NRC_UploadDownloadNotAccepted);
    }

    if (r->recv_len < UDS_0X36_REQ_BASE_LEN) {
        err = UDS_NRC_IncorrectMessageLengthOrInvalidFormat;
        goto fail;
    }

    blockSequenceCounter = r->recv_buf[1];

    if (!srv->RCRRP) {
        if (blockSequenceCounter != srv->xferBlockSequenceCounter) {
            err = UDS_NRC_RequestSequenceError;
            goto fail;
        } else {
            srv->xferBlockSequenceCounter++;
        }
    }

    if (srv->xferByteCounter + request_data_len > srv->xferTotalBytes) {
        err = UDS_NRC_TransferDataSuspended;
        goto fail;
    }

    {
        UDSTransferDataArgs_t args = {
            .data = &r->recv_buf[UDS_0X36_REQ_BASE_LEN],
            .len = r->recv_len - UDS_0X36_REQ_BASE_LEN,
            .maxRespLen = srv->xferBlockLength - UDS_0X36_RESP_BASE_LEN,
            .copyResponse = safe_copy,
        };

        r->send_buf[0] = UDS_RESPONSE_SID_OF(kSID_TRANSFER_DATA);
        r->send_buf[1] = blockSequenceCounter;
        r->send_len = UDS_0X36_RESP_BASE_LEN;

        err = EmitEvent(srv, UDS_EVT_TransferData, &args);

        switch (err) {
        case UDS_PositiveResponse:
            srv->xferByteCounter += request_data_len;
            return UDS_PositiveResponse;
        case UDS_NRC_RequestCorrectlyReceived_ResponsePending:
            return NegativeResponse(r, UDS_NRC_RequestCorrectlyReceived_ResponsePending);
        default:
            goto fail;
        }
    }

fail:
    ResetTransfer(srv);
    return NegativeResponse(r, err);
}

static uint8_t _0x37_RequestTransferExit(UDSServer_t *srv, UDSReq_t *r) {
    uint8_t err = UDS_PositiveResponse;

    if (!srv->xferIsActive) {
        return NegativeResponse(r, UDS_NRC_UploadDownloadNotAccepted);
    }

    r->send_buf[0] = UDS_RESPONSE_SID_OF(kSID_REQUEST_TRANSFER_EXIT);
    r->send_len = UDS_0X37_RESP_BASE_LEN;

    UDSRequestTransferExitArgs_t args = {
        .data = &r->recv_buf[UDS_0X37_REQ_BASE_LEN],
        .len = r->recv_len - UDS_0X37_REQ_BASE_LEN,
        .copyResponse = safe_copy,
    };

    err = EmitEvent(srv, UDS_EVT_RequestTransferExit, &args);

    switch (err) {
    case UDS_PositiveResponse:
        ResetTransfer(srv);
        return UDS_PositiveResponse;
    case UDS_NRC_RequestCorrectlyReceived_ResponsePending:
        return NegativeResponse(r, UDS_NRC_RequestCorrectlyReceived_ResponsePending);
    default:
        ResetTransfer(srv);
        return NegativeResponse(r, err);
    }
}
static uint8_t _0x38_RequestFileTransfer(UDSServer_t *srv, UDSReq_t *r) {
    uint8_t err = UDS_PositiveResponse;

    if (srv->xferIsActive) {
        return NegativeResponse(r, UDS_NRC_ConditionsNotCorrect);
    }
    if (r->recv_len < UDS_0X38_REQ_BASE_LEN) {
        return NegativeResponse(r, UDS_NRC_IncorrectMessageLengthOrInvalidFormat);
    }

    uint8_t operation = r->recv_buf[1];
    uint16_t file_path_len = ((uint16_t)r->recv_buf[2] << 8) + r->recv_buf[3];
    uint8_t file_mode = 0;
    if ((operation == kAddFile) || (operation == kReplaceFile) || (operation == kReadFile)) {
        file_mode = r->recv_buf[UDS_0X38_REQ_BASE_LEN + file_path_len];
    }
    size_t file_size_uncompressed = 0;
    size_t file_size_compressed = 0;
    if ((operation == kAddFile) || (operation == kReplaceFile)) {
        size_t size = r->recv_buf[UDS_0X38_REQ_BASE_LEN + file_path_len + 1];
        if (size > sizeof(size_t)) {
            return NegativeResponse(r, UDS_NRC_RequestOutOfRange);
        }
        for (size_t byteIdx = 0; byteIdx < size; byteIdx++) {
            size_t byte = r->recv_buf[UDS_0X38_REQ_BASE_LEN + file_path_len + 2 + byteIdx];
            uint8_t shiftBytes = size - 1 - byteIdx;
            file_size_uncompressed |= byte << (8 * shiftBytes);
        }
        for (size_t byteIdx = 0; byteIdx < size; byteIdx++) {
            size_t byte = r->recv_buf[UDS_0X38_REQ_BASE_LEN + file_path_len + 2 + size + byteIdx];
            uint8_t shiftBytes = size - 1 - byteIdx;
            file_size_compressed |= byte << (8 * shiftBytes);
        }
    }
    UDSRequestFileTransferArgs_t args = {
        .modeOfOperation = operation,
        .filePathLen = file_path_len,
        .filePath = &r->recv_buf[UDS_0X38_REQ_BASE_LEN],
        .dataFormatIdentifier = file_mode,
        .fileSizeUnCompressed = file_size_uncompressed,
        .fileSizeCompressed = file_size_compressed,
    };

    err = EmitEvent(srv, UDS_EVT_RequestFileTransfer, &args);

    if (UDS_PositiveResponse != err) {
        return NegativeResponse(r, err);
    }

    ResetTransfer(srv);
    srv->xferIsActive = true;
    srv->xferTotalBytes = args.fileSizeCompressed;
    srv->xferBlockLength = args.maxNumberOfBlockLength;

    if (args.maxNumberOfBlockLength > UDS_TP_MTU) {
        args.maxNumberOfBlockLength = UDS_TP_MTU;
    }

    r->send_buf[0] = UDS_RESPONSE_SID_OF(kSID_REQUEST_FILE_TRANSFER);
    r->send_buf[1] = args.modeOfOperation;
    r->send_buf[2] = sizeof(args.maxNumberOfBlockLength);
    for (uint8_t idx = 0; idx < sizeof(args.maxNumberOfBlockLength); idx++) {
        uint8_t shiftBytes = sizeof(args.maxNumberOfBlockLength) - 1 - idx;
        uint8_t byte = args.maxNumberOfBlockLength >> (shiftBytes * 8);
        r->send_buf[UDS_0X38_RESP_BASE_LEN + idx] = byte;
    }
    r->send_buf[UDS_0X38_RESP_BASE_LEN + sizeof(args.maxNumberOfBlockLength)] =
        args.dataFormatIdentifier;

    r->send_len = UDS_0X38_RESP_BASE_LEN + sizeof(args.maxNumberOfBlockLength) + 1;
    return UDS_PositiveResponse;
}

static uint8_t _0x3E_TesterPresent(UDSServer_t *srv, UDSReq_t *r) {
    if ((r->recv_len < UDS_0X3E_REQ_MIN_LEN) || (r->recv_len > UDS_0X3E_REQ_MAX_LEN)) {
        return NegativeResponse(r, UDS_NRC_IncorrectMessageLengthOrInvalidFormat);
    }
    uint8_t zeroSubFunction = r->recv_buf[1];

    switch (zeroSubFunction) {
    case 0x00:
    case 0x80:
        srv->s3_session_timeout_timer = UDSMillis() + srv->s3_ms;
        r->send_buf[0] = UDS_RESPONSE_SID_OF(kSID_TESTER_PRESENT);
        r->send_buf[1] = 0x00;
        r->send_len = UDS_0X3E_RESP_LEN;
        return UDS_PositiveResponse;
    default:
        return NegativeResponse(r, UDS_NRC_SubFunctionNotSupported);
    }
}

static uint8_t _0x85_ControlDTCSetting(UDSServer_t *srv, UDSReq_t *r) {
    if (r->recv_len < UDS_0X85_REQ_BASE_LEN) {
        return NegativeResponse(r, UDS_NRC_IncorrectMessageLengthOrInvalidFormat);
    }
    uint8_t dtcSettingType = r->recv_buf[1] & 0x3F;

    r->send_buf[0] = UDS_RESPONSE_SID_OF(kSID_CONTROL_DTC_SETTING);
    r->send_buf[1] = dtcSettingType;
    r->send_len = UDS_0X85_RESP_LEN;
    return UDS_PositiveResponse;
}

typedef uint8_t (*UDSService)(UDSServer_t *srv, UDSReq_t *r);

/**
 * @brief Get the internal service handler matching the given SID.
 * @param sid
 * @return pointer to UDSService or NULL if no match
 */
static UDSService getServiceForSID(uint8_t sid) {
    switch (sid) {
    case kSID_DIAGNOSTIC_SESSION_CONTROL:
        return _0x10_DiagnosticSessionControl;
    case kSID_ECU_RESET:
        return _0x11_ECUReset;
    case kSID_CLEAR_DIAGNOSTIC_INFORMATION:
        return NULL;
    case kSID_READ_DTC_INFORMATION:
        return NULL;
    case kSID_READ_DATA_BY_IDENTIFIER:
        return _0x22_ReadDataByIdentifier;
    case kSID_READ_MEMORY_BY_ADDRESS:
        return _0x23_ReadMemoryByAddress;
    case kSID_READ_SCALING_DATA_BY_IDENTIFIER:
        return NULL;
    case kSID_SECURITY_ACCESS:
        return _0x27_SecurityAccess;
    case kSID_COMMUNICATION_CONTROL:
        return _0x28_CommunicationControl;
    case kSID_READ_PERIODIC_DATA_BY_IDENTIFIER:
        return NULL;
    case kSID_DYNAMICALLY_DEFINE_DATA_IDENTIFIER:
        return NULL;
    case kSID_WRITE_DATA_BY_IDENTIFIER:
        return _0x2E_WriteDataByIdentifier;
    case kSID_INPUT_CONTROL_BY_IDENTIFIER:
        return NULL;
    case kSID_ROUTINE_CONTROL:
        return _0x31_RoutineControl;
    case kSID_REQUEST_DOWNLOAD:
        return _0x34_RequestDownload;
    case kSID_REQUEST_UPLOAD:
        return _0x35_RequestUpload;
    case kSID_TRANSFER_DATA:
        return _0x36_TransferData;
    case kSID_REQUEST_TRANSFER_EXIT:
        return _0x37_RequestTransferExit;
    case kSID_REQUEST_FILE_TRANSFER:
        return _0x38_RequestFileTransfer;
    case kSID_WRITE_MEMORY_BY_ADDRESS:
        return NULL;
    case kSID_TESTER_PRESENT:
        return _0x3E_TesterPresent;
    case kSID_ACCESS_TIMING_PARAMETER:
        return NULL;
    case kSID_SECURED_DATA_TRANSMISSION:
        return NULL;
    case kSID_CONTROL_DTC_SETTING:
        return _0x85_ControlDTCSetting;
    case kSID_RESPONSE_ON_EVENT:
        return NULL;
    default:
        UDS_LOGI(__FILE__, "no handler for request SID %x", sid);
        return NULL;
    }
}

/**
 * @brief Call the service if it exists, modifying the response if the spec calls for it.
 * @note see UDS-1 2013 7.5.5 Pseudo code example of server response behavior
 *
 * @param srv
 * @param addressingScheme
 */
static uint8_t evaluateServiceResponse(UDSServer_t *srv, UDSReq_t *r) {
    uint8_t response = UDS_PositiveResponse;
    bool suppressResponse = false;
    uint8_t sid = r->recv_buf[0];
    UDSService service = getServiceForSID(sid);

    if (NULL == srv->fn)
        return NegativeResponse(r, UDS_NRC_ServiceNotSupported);
    UDS_ASSERT(srv->fn); // service handler functions will call srv->fn. it must be valid

    switch (sid) {
    /* CASE Service_with_sub-function */
    /* test if service with sub-function is supported */
    case kSID_DIAGNOSTIC_SESSION_CONTROL:
    case kSID_ECU_RESET:
    case kSID_SECURITY_ACCESS:
    case kSID_COMMUNICATION_CONTROL:
    case kSID_ROUTINE_CONTROL:
    case kSID_TESTER_PRESENT:
    case kSID_CONTROL_DTC_SETTING: {
        assert(service);
        response = service(srv, r);

        bool suppressPosRspMsgIndicationBit = r->recv_buf[1] & 0x80;

        /* test if positive response is required and if responseCode is positive 0x00 */
        if ((suppressPosRspMsgIndicationBit) && (response == UDS_PositiveResponse) &&
            (
                // TODO: *not yet a NRC 0x78 response sent*
                true)) {
            suppressResponse = true;
        } else {
            suppressResponse = false;
        }
        break;
    }

    /* CASE Service_without_sub-function */
    /* test if service without sub-function is supported */
    case kSID_READ_DATA_BY_IDENTIFIER:
    case kSID_READ_MEMORY_BY_ADDRESS:
    case kSID_WRITE_DATA_BY_IDENTIFIER:
    case kSID_REQUEST_DOWNLOAD:
    case kSID_REQUEST_UPLOAD:
    case kSID_TRANSFER_DATA:
    case kSID_REQUEST_FILE_TRANSFER:
    case kSID_REQUEST_TRANSFER_EXIT: {
        assert(service);
        response = service(srv, r);
        break;
    }

    /* CASE Service_optional */
    case kSID_CLEAR_DIAGNOSTIC_INFORMATION:
    case kSID_READ_DTC_INFORMATION:
    case kSID_READ_SCALING_DATA_BY_IDENTIFIER:
    case kSID_READ_PERIODIC_DATA_BY_IDENTIFIER:
    case kSID_DYNAMICALLY_DEFINE_DATA_IDENTIFIER:
    case kSID_INPUT_CONTROL_BY_IDENTIFIER:
    case kSID_WRITE_MEMORY_BY_ADDRESS:
    case kSID_ACCESS_TIMING_PARAMETER:
    case kSID_SECURED_DATA_TRANSMISSION:
    case kSID_RESPONSE_ON_EVENT:
    default: {
        if (service) {
            response = service(srv, r);
        } else { /* getServiceForSID(sid) returned NULL*/
            UDSCustomArgs_t args = {
                .sid = sid,
                .optionRecord = &r->recv_buf[1],
                .len = r->recv_len - 1,
                .copyResponse = safe_copy,
            };

            r->send_buf[0] = UDS_RESPONSE_SID_OF(sid);
            r->send_len = 1;

            response = EmitEvent(srv, UDS_EVT_CUSTOM, &args);
            if (UDS_PositiveResponse != response)
                return NegativeResponse(r, response);
        }
        break;
    }
    }

    if ((UDS_A_TA_TYPE_FUNCTIONAL == r->info.A_TA_Type) &&
        ((UDS_NRC_ServiceNotSupported == response) ||
         (UDS_NRC_SubFunctionNotSupported == response) ||
         (UDS_NRC_ServiceNotSupportedInActiveSession == response) ||
         (UDS_NRC_SubFunctionNotSupportedInActiveSession == response) ||
         (UDS_NRC_RequestOutOfRange == response)) &&
        (
            // TODO: *not yet a NRC 0x78 response sent*
            true)) {
        suppressResponse = true; /* Suppress negative response message */
        NoResponse(r);
    } else {
        if (suppressResponse) { /* Suppress positive response message */
            NoResponse(r);
        } else { /* send negative or positive response */
            ;
        }
    }
    return response;
}

// ========================================================================
//                             Public Functions
// ========================================================================

UDSErr_t UDSServerInit(UDSServer_t *srv) {
    if (NULL == srv) {
        return UDS_ERR_INVALID_ARG;
    }
    memset(srv, 0, sizeof(UDSServer_t));
    srv->p2_ms = UDS_SERVER_DEFAULT_P2_MS;
    srv->p2_star_ms = UDS_SERVER_DEFAULT_P2_STAR_MS;
    srv->s3_ms = UDS_SERVER_DEFAULT_S3_MS;
    srv->sessionType = kDefaultSession;
    srv->p2_timer = UDSMillis() + srv->p2_ms;
    srv->s3_session_timeout_timer = UDSMillis() + srv->s3_ms;
    srv->sec_access_boot_delay_timer =
        UDSMillis() + UDS_SERVER_0x27_BRUTE_FORCE_MITIGATION_BOOT_DELAY_MS;
    srv->sec_access_auth_fail_timer = UDSMillis();
    return UDS_OK;
}

void UDSServerPoll(UDSServer_t *srv) {
    // UDS-1-2013 Figure 38: Session Timeout (S3)
    if (kDefaultSession != srv->sessionType &&
        UDSTimeAfter(UDSMillis(), srv->s3_session_timeout_timer)) {
        EmitEvent(srv, UDS_EVT_SessionTimeout, NULL);
    }

    if (srv->ecuResetScheduled && UDSTimeAfter(UDSMillis(), srv->ecuResetTimer)) {
        EmitEvent(srv, UDS_EVT_DoScheduledReset, &srv->ecuResetScheduled);
    }

    UDSTpPoll(srv->tp);

    UDSReq_t *r = &srv->r;

    if (srv->requestInProgress) {
        if (srv->RCRRP) {
            // responds only if
            // 1. changed (no longer RCRRP), or
            // 2. p2_timer has elapsed
            uint8_t response = evaluateServiceResponse(srv, r);
            if (UDS_NRC_RequestCorrectlyReceived_ResponsePending == response) {
                // it's the second time the service has responded with RCRRP
                srv->notReadyToReceive = true;
            } else {
                // No longer RCRRP'ing
                srv->RCRRP = false;
                srv->notReadyToReceive = false;

                // Not a consecutive 0x78 response, use p2 instead of p2_star * 0.3
                srv->p2_timer = UDSMillis() + srv->p2_ms;
            }
        }

        if (UDSTimeAfter(UDSMillis(), srv->p2_timer)) {
            ssize_t ret = 0;
            if (r->send_len) {
                ret = UDSTpSend(srv->tp, r->send_buf, r->send_len, NULL);
            }

            // TODO test injection of transport errors:
            if (ret < 0) {
                UDSErr_t err = UDS_ERR_TPORT;
                EmitEvent(srv, UDS_EVT_Err, &err);
                UDS_LOGI(__FILE__, "UDSTpSend failed with %zd\n", ret);
            }

            if (srv->RCRRP) {
                // ISO14229-2:2013 Table 4 footnote b
                // min time between consecutive 0x78 responses is 0.3 * p2*
                uint32_t wait_time = srv->p2_star_ms * 3 / 10;
                srv->p2_timer = UDSMillis() + wait_time;
            } else {
                srv->p2_timer = UDSMillis() + srv->p2_ms;
                UDSTpAckRecv(srv->tp);
                srv->requestInProgress = false;
            }
        }

    } else {
        if (srv->notReadyToReceive) {
            return; // cannot respond to request right now
        }
        r->recv_len = UDSTpPeek(srv->tp, &r->recv_buf, &r->info);
        r->send_buf_size = UDSTpGetSendBuf(srv->tp, &r->send_buf);
        if (r->recv_len > 0) {
            if (r->send_buf == NULL) {
                UDS_LOGI(__FILE__, "Send buf null\n");
            }
            if (r->recv_buf == NULL) {
                UDS_LOGI(__FILE__, "Recv buf null\n");
            }
            if (r->send_buf == NULL || r->recv_buf == NULL) {
                UDSErr_t err = UDS_ERR_TPORT;
                EmitEvent(srv, UDS_EVT_Err, &err);
                UDS_LOGI(__FILE__, "bad tport\n");
                return;
            }
            uint8_t response = evaluateServiceResponse(srv, r);
            srv->requestInProgress = true;
            if (UDS_NRC_RequestCorrectlyReceived_ResponsePending == response) {
                srv->RCRRP = true;
            }
        }
    }
}


#ifdef UDS_LINES
#line 1 "src/tp.c"
#endif


/**
 * @brief
 *
 * @param hdl
 * @param info, if NULL, the default values are used:
 *   A_Mtype: message type (diagnostic (DEFAULT), remote diagnostic, secure diagnostic, secure
 * remote diagnostic)
 * A_TA_Type: application target address type (physical (DEFAULT) or functional)
 * A_SA: unused
 * A_TA: unused
 * A_AE: unused
 * @return ssize_t
 */
ssize_t UDSTpGetSendBuf(struct UDSTp *hdl, uint8_t **buf) {
    UDS_ASSERT(hdl);
    UDS_ASSERT(hdl->get_send_buf);
    return hdl->get_send_buf(hdl, buf);
}

ssize_t UDSTpSend(struct UDSTp *hdl, const uint8_t *buf, ssize_t len, UDSSDU_t *info) {
    UDS_ASSERT(hdl);
    UDS_ASSERT(hdl->send);
    return hdl->send(hdl, (uint8_t *)buf, len, info);
}

UDSTpStatus_t UDSTpPoll(struct UDSTp *hdl) {
    UDS_ASSERT(hdl);
    UDS_ASSERT(hdl->poll);
    return hdl->poll(hdl);
}

ssize_t UDSTpPeek(struct UDSTp *hdl, uint8_t **buf, UDSSDU_t *info) {
    UDS_ASSERT(hdl);
    UDS_ASSERT(hdl->peek);
    return hdl->peek(hdl, buf, info);
}

const uint8_t *UDSTpGetRecvBuf(struct UDSTp *hdl, size_t *p_len) {
    UDS_ASSERT(hdl);
    ssize_t len = 0;
    uint8_t *buf = NULL;
    len = UDSTpPeek(hdl, &buf, NULL);
    if (len > 0) {
        if (p_len) {
            *p_len = len;
        }
        return buf;
    } else {
        return NULL;
    }
}

size_t UDSTpGetRecvLen(UDSTp_t *hdl) {
    UDS_ASSERT(hdl);
    size_t len = 0;
    UDSTpGetRecvBuf(hdl, &len);
    return len;
}

void UDSTpAckRecv(UDSTp_t *hdl) {
    UDS_ASSERT(hdl);
    hdl->ack_recv(hdl);
}


#ifdef UDS_LINES
#line 1 "src/util.c"
#endif



#if UDS_CUSTOM_MILLIS
#else
uint32_t UDSMillis(void) {
#if UDS_SYS == UDS_SYS_UNIX
    struct timeval te;
    gettimeofday(&te, NULL);
    long long milliseconds = te.tv_sec * 1000LL + te.tv_usec / 1000;
    return milliseconds;
#elif UDS_SYS == UDS_SYS_WINDOWS
    struct timespec ts;
    timespec_get(&ts, TIME_UTC);
    long long milliseconds = ts.tv_sec * 1000LL + ts.tv_nsec / 1000000;
    return milliseconds;
#elif UDS_SYS == UDS_SYS_ARDUINO
    return millis();
#elif UDS_SYS == UDS_SYS_ESP32
    return esp_timer_get_time() / 1000;
#else
#error "UDSMillis() undefined!"
#endif
}
#endif

bool UDSSecurityAccessLevelIsReserved(uint8_t securityLevel) {
    securityLevel &= 0x3f;
    return (0 == securityLevel || (0x43 <= securityLevel && securityLevel >= 0x5E) ||
            0x7F == securityLevel);
}

const char *UDSErrToStr(UDSErr_t err) {
#define MAKE_CASE(x)                                                                               \
    case x:                                                                                        \
        return #x;

    switch (err) {
        MAKE_CASE(UDS_FAIL)
        MAKE_CASE(UDS_OK)
        MAKE_CASE(UDS_NRC_GeneralReject)
        MAKE_CASE(UDS_NRC_ServiceNotSupported)
        MAKE_CASE(UDS_NRC_SubFunctionNotSupported)
        MAKE_CASE(UDS_NRC_IncorrectMessageLengthOrInvalidFormat)
        MAKE_CASE(UDS_NRC_ResponseTooLong)
        MAKE_CASE(UDS_NRC_BusyRepeatRequest)
        MAKE_CASE(UDS_NRC_ConditionsNotCorrect)
        MAKE_CASE(UDS_NRC_RequestSequenceError)
        MAKE_CASE(UDS_NRC_NoResponseFromSubnetComponent)
        MAKE_CASE(UDS_NRC_FailurePreventsExecutionOfRequestedAction)
        MAKE_CASE(UDS_NRC_RequestOutOfRange)
        MAKE_CASE(UDS_NRC_SecurityAccessDenied)
        MAKE_CASE(UDS_NRC_InvalidKey)
        MAKE_CASE(UDS_NRC_ExceedNumberOfAttempts)
        MAKE_CASE(UDS_NRC_RequiredTimeDelayNotExpired)
        MAKE_CASE(UDS_NRC_UploadDownloadNotAccepted)
        MAKE_CASE(UDS_NRC_TransferDataSuspended)
        MAKE_CASE(UDS_NRC_GeneralProgrammingFailure)
        MAKE_CASE(UDS_NRC_WrongBlockSequenceCounter)
        MAKE_CASE(UDS_NRC_RequestCorrectlyReceived_ResponsePending)
        MAKE_CASE(UDS_NRC_SubFunctionNotSupportedInActiveSession)
        MAKE_CASE(UDS_NRC_ServiceNotSupportedInActiveSession)
        MAKE_CASE(UDS_NRC_RpmTooHigh)
        MAKE_CASE(UDS_NRC_RpmTooLow)
        MAKE_CASE(UDS_NRC_EngineIsRunning)
        MAKE_CASE(UDS_NRC_EngineIsNotRunning)
        MAKE_CASE(UDS_NRC_EngineRunTimeTooLow)
        MAKE_CASE(UDS_NRC_TemperatureTooHigh)
        MAKE_CASE(UDS_NRC_TemperatureTooLow)
        MAKE_CASE(UDS_NRC_VehicleSpeedTooHigh)
        MAKE_CASE(UDS_NRC_VehicleSpeedTooLow)
        MAKE_CASE(UDS_NRC_ThrottlePedalTooHigh)
        MAKE_CASE(UDS_NRC_ThrottlePedalTooLow)
        MAKE_CASE(UDS_NRC_TransmissionRangeNotInNeutral)
        MAKE_CASE(UDS_NRC_TransmissionRangeNotInGear)
        MAKE_CASE(UDS_NRC_BrakeSwitchNotClosed)
        MAKE_CASE(UDS_NRC_ShifterLeverNotInPark)
        MAKE_CASE(UDS_NRC_TorqueConverterClutchLocked)
        MAKE_CASE(UDS_NRC_VoltageTooHigh)
        MAKE_CASE(UDS_NRC_VoltageTooLow)
        MAKE_CASE(UDS_ERR_TIMEOUT)
        MAKE_CASE(UDS_ERR_DID_MISMATCH)
        MAKE_CASE(UDS_ERR_SID_MISMATCH)
        MAKE_CASE(UDS_ERR_SUBFUNCTION_MISMATCH)
        MAKE_CASE(UDS_ERR_TPORT)
        MAKE_CASE(UDS_ERR_RESP_TOO_SHORT)
        MAKE_CASE(UDS_ERR_BUFSIZ)
        MAKE_CASE(UDS_ERR_INVALID_ARG)
        MAKE_CASE(UDS_ERR_BUSY)
    default:
        return "unknown";
    }
#undef MAKE_CASE
}

const char *UDSEvtToStr(UDSEvent_t evt) {
#define MAKE_CASE(x)                                                                               \
    case x:                                                                                        \
        return #x;

    switch (evt) {
        MAKE_CASE(UDS_EVT_Err)
        MAKE_CASE(UDS_EVT_DiagSessCtrl)
        MAKE_CASE(UDS_EVT_EcuReset)
        MAKE_CASE(UDS_EVT_ReadDataByIdent)
        MAKE_CASE(UDS_EVT_ReadMemByAddr)
        MAKE_CASE(UDS_EVT_CommCtrl)
        MAKE_CASE(UDS_EVT_SecAccessRequestSeed)
        MAKE_CASE(UDS_EVT_SecAccessValidateKey)
        MAKE_CASE(UDS_EVT_WriteDataByIdent)
        MAKE_CASE(UDS_EVT_RoutineCtrl)
        MAKE_CASE(UDS_EVT_RequestDownload)
        MAKE_CASE(UDS_EVT_RequestUpload)
        MAKE_CASE(UDS_EVT_TransferData)
        MAKE_CASE(UDS_EVT_RequestTransferExit)
        MAKE_CASE(UDS_EVT_SessionTimeout)
        MAKE_CASE(UDS_EVT_DoScheduledReset)
        MAKE_CASE(UDS_EVT_RequestFileTransfer)

        MAKE_CASE(UDS_EVT_Poll)
        MAKE_CASE(UDS_EVT_SendComplete)
        MAKE_CASE(UDS_EVT_ResponseReceived)
        MAKE_CASE(UDS_EVT_Idle)

    default:
        return "unknown";
    }
#undef MAKE_CASE
}


#ifdef UDS_LINES
#line 1 "src/log.c"
#endif


#include <stdio.h>
#include <stdarg.h>

void UDS_LogWrite(UDS_LogLevel_t level, const char *tag, const char *format, ...) {
    va_list list;
    va_start(list, format);
    vprintf(format, list);
    va_end(list);
}

void UDS_LogSDUInternal(UDS_LogLevel_t level, const char *tag, const uint8_t *buffer,
                        size_t buff_len, UDSSDU_t *info) {
    for (unsigned i = 0; i < buff_len; i++) {
        UDS_LogWrite(level, tag, "%02x ", buffer[i]);
    }
    UDS_LogWrite(level, tag, "\n");
}


#ifdef UDS_LINES
#line 1 "src/tp/isotp_c.c"
#endif
#if defined(UDS_TP_ISOTP_C)





static UDSTpStatus_t tp_poll(UDSTp_t *hdl) {
    UDS_ASSERT(hdl);
    UDSTpStatus_t status = 0;
    UDSISOTpC_t *impl = (UDSISOTpC_t *)hdl;
    isotp_poll(&impl->phys_link);
    if (impl->phys_link.send_status == ISOTP_SEND_STATUS_INPROGRESS) {
        status |= UDS_TP_SEND_IN_PROGRESS;
    }
    return status;
}

static int peek_link(IsoTpLink *link, uint8_t *buf, size_t bufsize, bool functional) {
    UDS_ASSERT(link);
    UDS_ASSERT(buf);
    int ret = -1;
    switch (link->receive_status) {
    case ISOTP_RECEIVE_STATUS_IDLE:
        ret = 0;
        goto done;
    case ISOTP_RECEIVE_STATUS_INPROGRESS:
        ret = 0;
        goto done;
    case ISOTP_RECEIVE_STATUS_FULL:
        ret = link->receive_size;
        UDS_LOGI(__FILE__, "The link is full. Copying %d bytes\n", ret);
        memmove(buf, link->receive_buffer, link->receive_size);
        break;
    default:
        UDS_LOGI(__FILE__, "receive_status %d not implemented\n", link->receive_status);
        ret = -1;
        goto done;
    }
done:
    return ret;
}

static ssize_t tp_peek(UDSTp_t *hdl, uint8_t **p_buf, UDSSDU_t *info) {
    UDS_ASSERT(hdl);
    UDS_ASSERT(p_buf);
    UDSISOTpC_t *tp = (UDSISOTpC_t *)hdl;
    if (ISOTP_RECEIVE_STATUS_FULL == tp->phys_link.receive_status) { // recv not yet acked
        *p_buf = tp->recv_buf;
        return tp->phys_link.receive_size;
    }
    int ret = -1;
    ret = peek_link(&tp->phys_link, tp->recv_buf, sizeof(tp->recv_buf), false);
    UDS_A_TA_Type_t ta_type = UDS_A_TA_TYPE_PHYSICAL;
    uint32_t ta = tp->phys_ta;
    uint32_t sa = tp->phys_sa;

    if (ret > 0) {
        UDS_LOGI(__FILE__, "just got %d bytes\n", ret);
        ta = tp->phys_sa;
        sa = tp->phys_ta;
        ta_type = UDS_A_TA_TYPE_PHYSICAL;
        *p_buf = tp->recv_buf;
        goto done;
    } else if (ret < 0) {
        goto done;
    } else {
        ret = peek_link(&tp->func_link, tp->recv_buf, sizeof(tp->recv_buf), true);
        if (ret > 0) {
            UDS_LOGI(__FILE__, "just got %d bytes on func link \n", ret);
            ta = tp->func_sa;
            sa = tp->func_ta;
            ta_type = UDS_A_TA_TYPE_FUNCTIONAL;
            *p_buf = tp->recv_buf;
            goto done;
        } else if (ret < 0) {
            goto done;
        }
    }
done:
    if (ret > 0) {
        if (info) {
            info->A_TA = ta;
            info->A_SA = sa;
            info->A_TA_Type = ta_type;
        }
    }
    return ret;
}

static ssize_t tp_send(UDSTp_t *hdl, uint8_t *buf, size_t len, UDSSDU_t *info) {
    UDS_ASSERT(hdl);
    ssize_t ret = -1;
    UDSISOTpC_t *tp = (UDSISOTpC_t *)hdl;
    IsoTpLink *link = NULL;
    const UDSTpAddr_t ta_type = info ? info->A_TA_Type : UDS_A_TA_TYPE_PHYSICAL;
    switch (ta_type) {
    case UDS_A_TA_TYPE_PHYSICAL:
        link = &tp->phys_link;
        break;
    case UDS_A_TA_TYPE_FUNCTIONAL:
        link = &tp->func_link;
        if (len > 7) {
            UDS_LOGI(__FILE__, "Cannot send more than 7 bytes via functional addressing\n");
            ret = -3;
            goto done;
        }
        break;
    default:
        ret = -4;
        goto done;
    }

    int send_status = isotp_send(link, buf, len);
    switch (send_status) {
    case ISOTP_RET_OK:
        ret = len;
        goto done;
    case ISOTP_RET_INPROGRESS:
    case ISOTP_RET_OVERFLOW:
    default:
        ret = send_status;
        goto done;
    }
done:
    return ret;
}

static void tp_ack_recv(UDSTp_t *hdl) {
    UDS_LOGI(__FILE__, "ack recv\n");
    UDS_ASSERT(hdl);
    UDSISOTpC_t *tp = (UDSISOTpC_t *)hdl;
    uint16_t out_size = 0;
    isotp_receive(&tp->phys_link, tp->recv_buf, sizeof(tp->recv_buf), &out_size);
}

static ssize_t tp_get_send_buf(UDSTp_t *hdl, uint8_t **p_buf) {
    UDS_ASSERT(hdl);
    UDSISOTpC_t *tp = (UDSISOTpC_t *)hdl;
    *p_buf = tp->send_buf;
    return sizeof(tp->send_buf);
}

UDSErr_t UDSISOTpCInit(UDSISOTpC_t *tp, const UDSISOTpCConfig_t *cfg) {
    if (cfg == NULL || tp == NULL) {
        return UDS_ERR_INVALID_ARG;
    }
    tp->hdl.poll = tp_poll;
    tp->hdl.send = tp_send;
    tp->hdl.peek = tp_peek;
    tp->hdl.ack_recv = tp_ack_recv;
    tp->hdl.get_send_buf = tp_get_send_buf;
    tp->phys_sa = cfg->source_addr;
    tp->phys_ta = cfg->target_addr;
    tp->func_sa = cfg->source_addr_func;
    tp->func_ta = cfg->target_addr_func;

    isotp_init_link(&tp->phys_link, tp->phys_ta, tp->send_buf, sizeof(tp->send_buf), tp->recv_buf,
                    sizeof(tp->recv_buf));
    isotp_init_link(&tp->func_link, tp->func_ta, tp->recv_buf, sizeof(tp->send_buf), tp->recv_buf,
                    sizeof(tp->recv_buf));
    return UDS_OK;
}

#endif


#ifdef UDS_LINES
#line 1 "src/tp/isotp_c_socketcan.c"
#endif
#if defined(UDS_TP_ISOTP_C_SOCKETCAN)




#include <linux/can.h>
#include <linux/can/raw.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>
#include <stdarg.h>

static int SetupSocketCAN(const char *ifname) {
    struct sockaddr_can addr;
    struct ifreq ifr;
    int sockfd = -1;

    if ((sockfd = socket(PF_CAN, SOCK_RAW | SOCK_NONBLOCK, CAN_RAW)) < 0) {
        perror("socket");
        goto done;
    }

    strcpy(ifr.ifr_name, ifname);
    ioctl(sockfd, SIOCGIFINDEX, &ifr);
    memset(&addr, 0, sizeof(addr));
    addr.can_family = AF_CAN;
    addr.can_ifindex = ifr.ifr_ifindex;
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
    }

done:
    return sockfd;
}

uint32_t isotp_user_get_us(void) { return UDSMillis() * 1000; }

void isotp_user_debug(const char *message, ...) {
    va_list args;
    va_start(args, message);
    vprintf(message, args);
    va_end(args);
}

int isotp_user_send_can(const uint32_t arbitration_id, const uint8_t *data, const uint8_t size,
                        void *user_data) {
    fflush(stdout);
    UDS_ASSERT(user_data);
    int sockfd = *(int *)user_data;
    struct can_frame frame = {0};
    frame.can_id = arbitration_id;
    frame.can_dlc = size;
    memmove(frame.data, data, size);
    if (write(sockfd, &frame, sizeof(struct can_frame)) != sizeof(struct can_frame)) {
        perror("Write err");
        return ISOTP_RET_ERROR;
    }
    return ISOTP_RET_OK;
}

static void SocketCANRecv(UDSTpISOTpC_t *tp) {
    UDS_ASSERT(tp);
    struct can_frame frame = {0};
    int nbytes = 0;

    for (;;) {
        nbytes = read(tp->fd, &frame, sizeof(struct can_frame));
        if (nbytes < 0) {
            if (EAGAIN == errno || EWOULDBLOCK == errno) {
                break;
            } else {
                perror("read");
            }
        } else if (nbytes == 0) {
            break;
        } else {
            if (frame.can_id == tp->phys_sa) {
                isotp_on_can_message(&tp->phys_link, frame.data, frame.can_dlc);
            } else if (frame.can_id == tp->func_sa) {
                if (ISOTP_RECEIVE_STATUS_IDLE != tp->phys_link.receive_status) {
                    UDS_LOGI(__FILE__,
                             "func frame received but cannot process because link is not idle");
                    return;
                }
                // TODO: reject if it's longer than a single frame
                isotp_on_can_message(&tp->func_link, frame.data, frame.can_dlc);
            }
        }
    }
}

static UDSTpStatus_t isotp_c_socketcan_tp_poll(UDSTp_t *hdl) {
    UDS_ASSERT(hdl);
    UDSTpStatus_t status = 0;
    UDSTpISOTpC_t *impl = (UDSTpISOTpC_t *)hdl;
    SocketCANRecv(impl);
    isotp_poll(&impl->phys_link);
    if (impl->phys_link.send_status == ISOTP_SEND_STATUS_INPROGRESS) {
        status |= UDS_TP_SEND_IN_PROGRESS;
    }
    if (impl->phys_link.send_status == ISOTP_SEND_STATUS_ERROR) {
        status |= UDS_TP_ERR;
    }
    return status;
}

static int isotp_c_socketcan_tp_peek_link(IsoTpLink *link, uint8_t *buf, size_t bufsize,
                                          bool functional) {
    UDS_ASSERT(link);
    UDS_ASSERT(buf);
    int ret = -1;
    switch (link->receive_status) {
    case ISOTP_RECEIVE_STATUS_IDLE:
        ret = 0;
        goto done;
    case ISOTP_RECEIVE_STATUS_INPROGRESS:
        ret = 0;
        goto done;
    case ISOTP_RECEIVE_STATUS_FULL:
        ret = link->receive_size;
        UDS_LOGI(__FILE__, "The link is full. Copying %d bytes", ret);
        memmove(buf, link->receive_buffer, link->receive_size);
        break;
    default:
        UDS_LOGI(__FILE__, "receive_status %d not implemented\n", link->receive_status);
        ret = -1;
        goto done;
    }
done:
    return ret;
}

static ssize_t isotp_c_socketcan_tp_peek(UDSTp_t *hdl, uint8_t **p_buf, UDSSDU_t *info) {
    UDS_ASSERT(hdl);
    UDS_ASSERT(p_buf);
    UDSTpISOTpC_t *tp = (UDSTpISOTpC_t *)hdl;
    if (ISOTP_RECEIVE_STATUS_FULL == tp->phys_link.receive_status) { // recv not yet acked
        *p_buf = tp->recv_buf;
        return tp->phys_link.receive_size;
    }
    int ret = -1;
    ret = isotp_c_socketcan_tp_peek_link(&tp->phys_link, tp->recv_buf, sizeof(tp->recv_buf), false);
    UDS_A_TA_Type_t ta_type = UDS_A_TA_TYPE_PHYSICAL;
    uint32_t ta = tp->phys_ta;
    uint32_t sa = tp->phys_sa;

    if (ret > 0) {
        UDS_LOGI(__FILE__, "just got %d bytes", ret);
        ta = tp->phys_sa;
        sa = tp->phys_ta;
        ta_type = UDS_A_TA_TYPE_PHYSICAL;
        *p_buf = tp->recv_buf;
        goto done;
    } else if (ret < 0) {
        goto done;
    } else {
        ret = isotp_c_socketcan_tp_peek_link(&tp->func_link, tp->recv_buf, sizeof(tp->recv_buf),
                                             true);
        if (ret > 0) {
            UDS_LOGI(__FILE__, "just got %d bytes on func link", ret);
            ta = tp->func_sa;
            sa = tp->func_ta;
            ta_type = UDS_A_TA_TYPE_FUNCTIONAL;
            *p_buf = tp->recv_buf;
            goto done;
        } else if (ret < 0) {
            goto done;
        }
    }
done:
    if (ret > 0) {
        if (info) {
            info->A_TA = ta;
            info->A_SA = sa;
            info->A_TA_Type = ta_type;
        }
        UDS_LOGD(__FILE__, "%s recv, 0x%03x (%s), ", tp->tag, ta,
                 ta_type == UDS_A_TA_TYPE_PHYSICAL ? "phys" : "func");
        UDS_LOG_SDU(__FILE__, *p_buf, ret, info);
    }
    return ret;
}

static ssize_t isotp_c_socketcan_tp_send(UDSTp_t *hdl, uint8_t *buf, size_t len, UDSSDU_t *info) {
    UDS_ASSERT(hdl);
    ssize_t ret = -1;
    UDSTpISOTpC_t *tp = (UDSTpISOTpC_t *)hdl;
    IsoTpLink *link = NULL;
    const UDSTpAddr_t ta_type = info ? info->A_TA_Type : UDS_A_TA_TYPE_PHYSICAL;
    const uint32_t ta = ta_type == UDS_A_TA_TYPE_PHYSICAL ? tp->phys_ta : tp->func_ta;
    switch (ta_type) {
    case UDS_A_TA_TYPE_PHYSICAL:
        link = &tp->phys_link;
        break;
    case UDS_A_TA_TYPE_FUNCTIONAL:
        link = &tp->func_link;
        if (len > 7) {
            UDS_LOGI(__FILE__, "Cannot send more than 7 bytes via functional addressing");
            ret = -3;
            goto done;
        }
        break;
    default:
        ret = -4;
        goto done;
    }

    int send_status = isotp_send(link, buf, len);
    switch (send_status) {
    case ISOTP_RET_OK:
        ret = len;
        goto done;
    case ISOTP_RET_INPROGRESS:
    case ISOTP_RET_OVERFLOW:
    default:
        ret = send_status;
        goto done;
    }
done:
    UDS_LOGD(__FILE__, "'%s' sends %d bytes to 0x%03x (%s)", tp->tag, len, ta,
             ta_type == UDS_A_TA_TYPE_PHYSICAL ? "phys" : "func");
    UDS_LOG_SDU(__FILE__, buf, len, info);
    return ret;
}

static void isotp_c_socketcan_tp_ack_recv(UDSTp_t *hdl) {
    UDS_LOGI(__FILE__, "ack recv\n");
    UDS_ASSERT(hdl);
    UDSTpISOTpC_t *tp = (UDSTpISOTpC_t *)hdl;
    uint16_t out_size = 0;
    isotp_receive(&tp->phys_link, tp->recv_buf, sizeof(tp->recv_buf), &out_size);
}

static ssize_t isotp_c_socketcan_tp_get_send_buf(UDSTp_t *hdl, uint8_t **p_buf) {
    UDS_ASSERT(hdl);
    UDSTpISOTpC_t *tp = (UDSTpISOTpC_t *)hdl;
    *p_buf = tp->send_buf;
    return sizeof(tp->send_buf);
}

UDSErr_t UDSTpISOTpCInit(UDSTpISOTpC_t *tp, const char *ifname, uint32_t source_addr,
                         uint32_t target_addr, uint32_t source_addr_func,
                         uint32_t target_addr_func) {
    UDS_ASSERT(tp);
    UDS_ASSERT(ifname);
    tp->hdl.poll = isotp_c_socketcan_tp_poll;
    tp->hdl.send = isotp_c_socketcan_tp_send;
    tp->hdl.peek = isotp_c_socketcan_tp_peek;
    tp->hdl.ack_recv = isotp_c_socketcan_tp_ack_recv;
    tp->hdl.get_send_buf = isotp_c_socketcan_tp_get_send_buf;
    tp->phys_sa = source_addr;
    tp->phys_ta = target_addr;
    tp->func_sa = source_addr_func;
    tp->func_ta = target_addr;
    tp->fd = SetupSocketCAN(ifname);

    isotp_init_link(&tp->phys_link, target_addr, tp->send_buf, sizeof(tp->send_buf), tp->recv_buf,
                    sizeof(tp->recv_buf));
    isotp_init_link(&tp->func_link, target_addr_func, tp->recv_buf, sizeof(tp->send_buf),
                    tp->recv_buf, sizeof(tp->recv_buf));

    tp->phys_link.user_send_can_arg = &(tp->fd);
    tp->func_link.user_send_can_arg = &(tp->fd);

    return UDS_OK;
}

void UDSTpISOTpCDeinit(UDSTpISOTpC_t *tp) {
    UDS_ASSERT(tp);
    close(tp->fd);
    tp->fd = -1;
}

#endif


#ifdef UDS_LINES
#line 1 "src/tp/isotp_sock.c"
#endif
#if defined(UDS_TP_ISOTP_SOCK)



#include <string.h>
#include <errno.h>
#include <linux/can.h>
#include <linux/can/isotp.h>
#include <net/if.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static UDSTpStatus_t isotp_sock_tp_poll(UDSTp_t *hdl) {
    UDSTpIsoTpSock_t *impl = (UDSTpIsoTpSock_t *)hdl;
    UDSTpStatus_t status = 0;
    int ret = 0;
    int fds[2] = {impl->phys_fd, impl->func_fd};
    struct pollfd pfds[2] = {0};
    pfds[0].fd = impl->phys_fd;
    pfds[0].events = POLLERR;
    pfds[0].revents = 0;

    pfds[1].fd = impl->func_fd;
    pfds[1].events = POLLERR;
    pfds[1].revents = 0;

    ret = poll(pfds, 2, 1);
    if (ret < 0) {
        perror("poll");
    } else if (ret == 0) {
        ; // no error
    } else {
        for (int i = 0; i < 2; i++) {
            struct pollfd pfd = pfds[i];
            if (pfd.revents & POLLERR) {
                int pending_err = 0;
                socklen_t len = sizeof(pending_err);
                if (!getsockopt(fds[i], SOL_SOCKET, SO_ERROR, &pending_err, &len) && pending_err) {
                    switch (pending_err) {
                    case ECOMM:
                        UDS_LOGE(__FILE__, "ECOMM: Communication error on send");
                        status |= UDS_TP_ERR;
                        break;
                    default:
                        UDS_LOGE(__FILE__, "Asynchronous socket error: %s (%d)\n",
                                 strerror(pending_err), pending_err);
                        status |= UDS_TP_ERR;
                        break;
                    }
                } else {
                    UDS_LOGE(__FILE__, "POLLERR was set, but no error returned via SO_ERROR?");
                }
            } else {
                UDS_LOGE(__FILE__, "poll() returned, but no POLLERR. revents=0x%x", pfd.revents);
            }
        }
    }
    return status;
}

static ssize_t tp_recv_once(int fd, uint8_t *buf, size_t size) {
    ssize_t ret = read(fd, buf, size);
    if (ret < 0) {
        if (EAGAIN == errno || EWOULDBLOCK == errno) {
            ret = 0;
        } else {
            UDS_LOGI(__FILE__, "read failed: %ld with errno: %d\n", ret, errno);
            if (EILSEQ == errno) {
                UDS_LOGI(__FILE__, "Perhaps I received multiple responses?");
            }
        }
    }
    return ret;
}

static ssize_t isotp_sock_tp_peek(UDSTp_t *hdl, uint8_t **p_buf, UDSSDU_t *info) {
    UDS_ASSERT(hdl);
    UDS_ASSERT(p_buf);
    ssize_t ret = 0;
    UDSTpIsoTpSock_t *impl = (UDSTpIsoTpSock_t *)hdl;
    *p_buf = impl->recv_buf;
    UDSSDU_t *msg = &impl->recv_info;
    if (impl->recv_len) { // recv not yet acked
        ret = impl->recv_len;
        goto done;
    }

    // recv acked, OK to receive
    ret = tp_recv_once(impl->phys_fd, impl->recv_buf, sizeof(impl->recv_buf));
    if (ret > 0) {
        msg->A_TA = impl->phys_sa;
        msg->A_SA = impl->phys_ta;
        msg->A_TA_Type = UDS_A_TA_TYPE_PHYSICAL;
    } else {
        ret = tp_recv_once(impl->func_fd, impl->recv_buf, sizeof(impl->recv_buf));
        if (ret > 0) {
            msg->A_TA = impl->func_sa;
            msg->A_SA = impl->func_ta;
            msg->A_TA_Type = UDS_A_TA_TYPE_FUNCTIONAL;
        }
    }

    if (ret > 0) {
        UDS_LOGD(__FILE__, "'%s' received %d bytes from 0x%03x (%s), ", impl->tag, ret, msg->A_TA,
                 msg->A_TA_Type == UDS_A_TA_TYPE_PHYSICAL ? "phys" : "func");
        UDS_LOG_SDU(__FILE__, impl->recv_buf, ret, msg);
    }

done:
    if (ret > 0) {
        impl->recv_len = ret;
        if (info) {
            *info = *msg;
        }
    }
    return ret;
}

static void isotp_sock_tp_ack_recv(UDSTp_t *hdl) {
    UDS_ASSERT(hdl);
    UDSTpIsoTpSock_t *impl = (UDSTpIsoTpSock_t *)hdl;
    impl->recv_len = 0;
}

static ssize_t isotp_sock_tp_send(UDSTp_t *hdl, uint8_t *buf, size_t len, UDSSDU_t *info) {
    UDS_ASSERT(hdl);
    ssize_t ret = -1;
    UDSTpIsoTpSock_t *impl = (UDSTpIsoTpSock_t *)hdl;
    int fd;
    const UDSTpAddr_t ta_type = info ? info->A_TA_Type : UDS_A_TA_TYPE_PHYSICAL;

    if (UDS_A_TA_TYPE_PHYSICAL == ta_type) {
        fd = impl->phys_fd;
    } else if (UDS_A_TA_TYPE_FUNCTIONAL == ta_type) {
        if (len > 7) {
            UDS_LOGI(__FILE__, "UDSTpIsoTpSock: functional request too large");
            return -1;
        }
        fd = impl->func_fd;
    } else {
        ret = -4;
        goto done;
    }
    ret = write(fd, buf, len);
    if (ret < 0) {
        perror("write");
    }
done:
    int ta = ta_type == UDS_A_TA_TYPE_PHYSICAL ? impl->phys_ta : impl->func_ta;
    UDS_LOGD(__FILE__, "'%s' sends %d bytes to 0x%03x (%s)", impl->tag, len, ta,
             ta_type == UDS_A_TA_TYPE_PHYSICAL ? "phys" : "func");
    UDS_LOG_SDU(__FILE__, buf, len, info);

    return ret;
}

static ssize_t isotp_sock_tp_get_send_buf(UDSTp_t *hdl, uint8_t **p_buf) {
    UDS_ASSERT(hdl);
    UDSTpIsoTpSock_t *impl = (UDSTpIsoTpSock_t *)hdl;
    *p_buf = impl->send_buf;
    return sizeof(impl->send_buf);
}

static int LinuxSockBind(const char *if_name, uint32_t rxid, uint32_t txid, bool functional) {
    int fd = 0;
    if ((fd = socket(AF_CAN, SOCK_DGRAM | SOCK_NONBLOCK, CAN_ISOTP)) < 0) {
        perror("Socket");
        return -1;
    }

    struct can_isotp_fc_options fcopts = {
        .bs = 0x10,
        .stmin = 3,
        .wftmax = 0,
    };
    if (setsockopt(fd, SOL_CAN_ISOTP, CAN_ISOTP_RECV_FC, &fcopts, sizeof(fcopts)) < 0) {
        perror("setsockopt");
        return -1;
    }

    struct can_isotp_options opts;
    memset(&opts, 0, sizeof(opts));

    if (functional) {
        UDS_LOGI(__FILE__, "configuring fd: %d as functional", fd);
        // configure the socket as listen-only to avoid sending FC frames
        opts.flags |= CAN_ISOTP_LISTEN_MODE;
    }

    if (setsockopt(fd, SOL_CAN_ISOTP, CAN_ISOTP_OPTS, &opts, sizeof(opts)) < 0) {
        perror("setsockopt (isotp_options):");
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
    ioctl(fd, SIOCGIFINDEX, &ifr);

    struct sockaddr_can addr;
    memset(&addr, 0, sizeof(addr));
    addr.can_family = AF_CAN;
    addr.can_addr.tp.rx_id = rxid;
    addr.can_addr.tp.tx_id = txid;
    addr.can_ifindex = ifr.ifr_ifindex;

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        UDS_LOGI(__FILE__, "Bind: %s %s\n", strerror(errno), if_name);
        return -1;
    }
    return fd;
}

UDSErr_t UDSTpIsoTpSockInitServer(UDSTpIsoTpSock_t *tp, const char *ifname, uint32_t source_addr,
                                  uint32_t target_addr, uint32_t source_addr_func) {
    UDS_ASSERT(tp);
    memset(tp, 0, sizeof(*tp));
    tp->hdl.peek = isotp_sock_tp_peek;
    tp->hdl.send = isotp_sock_tp_send;
    tp->hdl.poll = isotp_sock_tp_poll;
    tp->hdl.ack_recv = isotp_sock_tp_ack_recv;
    tp->hdl.get_send_buf = isotp_sock_tp_get_send_buf;
    tp->phys_sa = source_addr;
    tp->phys_ta = target_addr;
    tp->func_sa = source_addr_func;

    tp->phys_fd = LinuxSockBind(ifname, source_addr, target_addr, false);
    tp->func_fd = LinuxSockBind(ifname, source_addr_func, 0, true);
    if (tp->phys_fd < 0 || tp->func_fd < 0) {
        UDS_LOGI(__FILE__, "foo\n");
        fflush(stdout);
        return UDS_FAIL;
    }
    const char *tag = "server";
    memmove(tp->tag, tag, strlen(tag));
    UDS_LOGI(__FILE__, "%s initialized phys link rx 0x%03x tx 0x%03x func link rx 0x%03x tx 0x%03x",
             strlen(tp->tag) ? tp->tag : "server", source_addr, target_addr, source_addr_func,
             target_addr);
    return UDS_OK;
}

UDSErr_t UDSTpIsoTpSockInitClient(UDSTpIsoTpSock_t *tp, const char *ifname, uint32_t source_addr,
                                  uint32_t target_addr, uint32_t target_addr_func) {
    UDS_ASSERT(tp);
    memset(tp, 0, sizeof(*tp));
    tp->hdl.peek = isotp_sock_tp_peek;
    tp->hdl.send = isotp_sock_tp_send;
    tp->hdl.poll = isotp_sock_tp_poll;
    tp->hdl.ack_recv = isotp_sock_tp_ack_recv;
    tp->hdl.get_send_buf = isotp_sock_tp_get_send_buf;
    tp->func_ta = target_addr_func;
    tp->phys_ta = target_addr;
    tp->phys_sa = source_addr;

    tp->phys_fd = LinuxSockBind(ifname, source_addr, target_addr, false);
    tp->func_fd = LinuxSockBind(ifname, 0, target_addr_func, true);
    if (tp->phys_fd < 0 || tp->func_fd < 0) {
        return UDS_FAIL;
    }
    const char *tag = "client";
    memmove(tp->tag, tag, strlen(tag));
    UDS_LOGI(__FILE__,
             "%s initialized phys link (fd %d) rx 0x%03x tx 0x%03x func link (fd %d) rx 0x%03x tx "
             "0x%03x",
             strlen(tp->tag) ? tp->tag : "client", tp->phys_fd, source_addr, target_addr,
             tp->func_fd, source_addr, target_addr_func);
    return UDS_OK;
}

void UDSTpIsoTpSockDeinit(UDSTpIsoTpSock_t *tp) {
    if (tp) {
        if (close(tp->phys_fd) < 0) {
            perror("failed to close socket");
        }
        if (close(tp->func_fd) < 0) {
            perror("failed to close socket");
        }
    }
}

#endif


#ifdef UDS_LINES
#line 1 "src/tp/isotp_mock.c"
#endif
#if defined(UDS_TP_ISOTP_MOCK)



#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_NUM_TP 16
#define NUM_MSGS 8
static ISOTPMock_t *TPs[MAX_NUM_TP];
static unsigned TPCount = 0;
static FILE *LogFile = NULL;
static struct Msg {
    uint8_t buf[UDS_ISOTP_MTU];
    size_t len;
    UDSSDU_t info;
    uint32_t scheduled_tx_time;
    ISOTPMock_t *sender;
} msgs[NUM_MSGS];
static unsigned MsgCount = 0;

static void NetworkPoll(void) {
    for (unsigned i = 0; i < MsgCount; i++) {
        if (UDSTimeAfter(UDSMillis(), msgs[i].scheduled_tx_time)) {
            bool found = false;
            for (unsigned j = 0; j < TPCount; j++) {
                ISOTPMock_t *tp = TPs[j];
                if (tp->sa_phys == msgs[i].info.A_TA || tp->sa_func == msgs[i].info.A_TA) {
                    found = true;
                    if (tp->recv_len > 0) {
                        fprintf(stderr, "TPMock: %s recv buffer is already full. Message dropped\n",
                                tp->name);
                        continue;
                    }

                    UDS_LOGD(__FILE__,
                             "%s receives %d bytes from TA=0x%03X (A_TA_Type=%s):", tp->name,
                             msgs[i].len, msgs[i].info.A_TA,
                             msgs[i].info.A_TA_Type == UDS_A_TA_TYPE_PHYSICAL ? "PHYSICAL"
                                                                              : "FUNCTIONAL");
                    UDS_LOG_SDU(__FILE__, msgs[i].buf, msgs[i].len, &(msgs[i].info));

                    memmove(tp->recv_buf, msgs[i].buf, msgs[i].len);
                    tp->recv_len = msgs[i].len;
                    tp->recv_info = msgs[i].info;
                }
            }

            if (!found) {
                UDS_LOGW(__FILE__, "TPMock: no matching receiver for message");
            }

            for (unsigned j = i + 1; j < MsgCount; j++) {
                msgs[j - 1] = msgs[j];
            }
            MsgCount--;
            i--;
        }
    }
}

static ssize_t mock_tp_peek(struct UDSTp *hdl, uint8_t **p_buf, UDSSDU_t *info) {
    assert(hdl);
    assert(p_buf);
    ISOTPMock_t *tp = (ISOTPMock_t *)hdl;
    if (p_buf) {
        *p_buf = tp->recv_buf;
    }
    if (info) {
        *info = tp->recv_info;
    }
    return tp->recv_len;
}

static ssize_t mock_tp_send(struct UDSTp *hdl, uint8_t *buf, size_t len, UDSSDU_t *info) {
    assert(hdl);
    ISOTPMock_t *tp = (ISOTPMock_t *)hdl;
    if (MsgCount >= NUM_MSGS) {
        UDS_LOGW(__FILE__, "mock_tp_send: too many messages in the queue");
        return -1;
    }
    struct Msg *m = &msgs[MsgCount++];
    UDSTpAddr_t ta_type = info == NULL ? UDS_A_TA_TYPE_PHYSICAL : info->A_TA_Type;
    m->len = len;
    m->info.A_AE = info == NULL ? 0 : info->A_AE;
    if (UDS_A_TA_TYPE_PHYSICAL == ta_type) {
        m->info.A_TA = tp->ta_phys;
        m->info.A_SA = tp->sa_phys;
    } else if (UDS_A_TA_TYPE_FUNCTIONAL == ta_type) {

        // This condition is only true for standard CAN.
        // Technically CAN-FD may also be used in ISO-TP.
        // TODO: add profiles to isotp_mock
        if (len > 7) {
            UDS_LOGW(__FILE__, "mock_tp_send: functional message too long: %d", len);
            return -1;
        }
        m->info.A_TA = tp->ta_func;
        m->info.A_SA = tp->sa_func;
    } else {
        UDS_LOGW(__FILE__, "mock_tp_send: unknown TA type: %d", ta_type);
        return -1;
    }
    m->info.A_TA_Type = ta_type;
    m->scheduled_tx_time = UDSMillis() + tp->send_tx_delay_ms;
    memmove(m->buf, buf, len);

    UDS_LOGD(__FILE__, "%s sends %d bytes to TA=0x%03X (A_TA_Type=%s):", tp->name, len,
             m->info.A_TA, m->info.A_TA_Type == UDS_A_TA_TYPE_PHYSICAL ? "PHYSICAL" : "FUNCTIONAL");
    UDS_LOG_SDU(__FILE__, buf, len, &m->info);

    return len;
}

static UDSTpStatus_t mock_tp_poll(struct UDSTp *hdl) {
    NetworkPoll();
    // todo: make this status reflect TX time
    return UDS_TP_IDLE;
}

static ssize_t mock_tp_get_send_buf(struct UDSTp *hdl, uint8_t **p_buf) {
    assert(hdl);
    assert(p_buf);
    ISOTPMock_t *tp = (ISOTPMock_t *)hdl;
    *p_buf = tp->send_buf;
    return sizeof(tp->send_buf);
}

static void mock_tp_ack_recv(struct UDSTp *hdl) {
    assert(hdl);
    ISOTPMock_t *tp = (ISOTPMock_t *)hdl;
    tp->recv_len = 0;
}

static_assert(offsetof(ISOTPMock_t, hdl) == 0, "ISOTPMock_t must not have any members before hdl");

static void ISOTPMockAttach(ISOTPMock_t *tp, ISOTPMockArgs_t *args) {
    assert(tp);
    assert(args);
    assert(TPCount < MAX_NUM_TP);
    TPs[TPCount++] = tp;
    tp->hdl.peek = mock_tp_peek;
    tp->hdl.send = mock_tp_send;
    tp->hdl.poll = mock_tp_poll;
    tp->hdl.get_send_buf = mock_tp_get_send_buf;
    tp->hdl.ack_recv = mock_tp_ack_recv;
    tp->sa_func = args->sa_func;
    tp->sa_phys = args->sa_phys;
    tp->ta_func = args->ta_func;
    tp->ta_phys = args->ta_phys;
    tp->recv_len = 0;
    UDS_LOGV(__FILE__, "attached %s. TPCount: %d", tp->name, TPCount);
}

static void ISOTPMockDetach(ISOTPMock_t *tp) {
    assert(tp);
    for (unsigned i = 0; i < TPCount; i++) {
        if (TPs[i] == tp) {
            for (unsigned j = i + 1; j < TPCount; j++) {
                TPs[j - 1] = TPs[j];
            }
            TPCount--;
            UDS_LOGV(__FILE__, "TPMock: detached %s. TPCount: %d", tp->name, TPCount);
            return;
        }
    }
    assert(false);
}

UDSTp_t *ISOTPMockNew(const char *name, ISOTPMockArgs_t *args) {
    if (TPCount >= MAX_NUM_TP) {
        UDS_LOGI(__FILE__, "TPCount: %d, too many TPs\n", TPCount);
        return NULL;
    }
    ISOTPMock_t *tp = malloc(sizeof(ISOTPMock_t));
    if (name) {
        strncpy(tp->name, name, sizeof(tp->name));
    } else {
        snprintf(tp->name, sizeof(tp->name), "TPMock%d", TPCount);
    }
    ISOTPMockAttach(tp, args);
    return &tp->hdl;
}

void ISOTPMockConnect(UDSTp_t *tp1, UDSTp_t *tp2);

void ISOTPMockLogToFile(const char *filename) {
    if (LogFile) {
        fprintf(stderr, "Log file is already open\n");
        return;
    }
    if (!filename) {
        fprintf(stderr, "Filename is NULL\n");
        return;
    }
    // create file
    LogFile = fopen(filename, "w");
    if (!LogFile) {
        fprintf(stderr, "Failed to open log file %s\n", filename);
        return;
    }
}

void ISOTPMockLogToStdout(void) {
    if (LogFile) {
        return;
    }
    LogFile = stdout;
}

void ISOTPMockReset(void) {
    memset(TPs, 0, sizeof(TPs));
    TPCount = 0;
    memset(msgs, 0, sizeof(msgs));
    MsgCount = 0;
}

void ISOTPMockFree(UDSTp_t *tp) {
    ISOTPMock_t *tpm = (ISOTPMock_t *)tp;
    ISOTPMockDetach(tpm);
    free(tp);
}

#endif

#if defined(UDS_TP_ISOTP_C)
#ifndef ISO_TP_USER_SEND_CAN_ARG
#error
#endif
#include <stdint.h>



///////////////////////////////////////////////////////
///                 STATIC FUNCTIONS                ///
///////////////////////////////////////////////////////

/* st_min to microsecond */
static uint8_t isotp_us_to_st_min(uint32_t us) {
    if (us <= 127000) {
        if (us >= 100 && us <= 900) {
            return (uint8_t)(0xF0 + (us / 100));
        } else {
            return (uint8_t)(us / 1000u);
        }
    }

    return 0;
}

/* st_min to usec  */
static uint32_t isotp_st_min_to_us(uint8_t st_min) {
    if (st_min <= 0x7F) {
        return st_min * 1000;
    } else if (st_min >= 0xF1 && st_min <= 0xF9) {
        return (st_min - 0xF0) * 100;
    }
    return 0;
}

static int isotp_send_flow_control(const IsoTpLink* link, uint8_t flow_status, uint8_t block_size, uint32_t st_min_us) {

    IsoTpCanMessage message;
    int ret;
    uint8_t size = 0;

    /* setup message  */
    message.as.flow_control.type = ISOTP_PCI_TYPE_FLOW_CONTROL_FRAME;
    message.as.flow_control.FS = flow_status;
    message.as.flow_control.BS = block_size;
    message.as.flow_control.STmin = isotp_us_to_st_min(st_min_us);

    /* send message */
#ifdef ISO_TP_FRAME_PADDING
    (void) memset(message.as.flow_control.reserve, ISO_TP_FRAME_PADDING_VALUE, sizeof(message.as.flow_control.reserve));
    size = sizeof(message);
#else
    size = 3;
#endif

    ret = isotp_user_send_can(link->send_arbitration_id, message.as.data_array.ptr, size
    #if defined (ISO_TP_USER_SEND_CAN_ARG)
    ,link->user_send_can_arg
    #endif
    );

    return ret;
}

static int isotp_send_single_frame(const IsoTpLink* link, uint32_t id) {

    IsoTpCanMessage message;
    int ret;
    uint8_t size = 0;

    /* multi frame message length must greater than 7  */
    assert(link->send_size <= 7);

    /* setup message  */
    message.as.single_frame.type = ISOTP_PCI_TYPE_SINGLE;
    message.as.single_frame.SF_DL = (uint8_t) link->send_size;
    (void) memcpy(message.as.single_frame.data, link->send_buffer, link->send_size);

    /* send message */
#ifdef ISO_TP_FRAME_PADDING
    (void) memset(message.as.single_frame.data + link->send_size, ISO_TP_FRAME_PADDING_VALUE, sizeof(message.as.single_frame.data) - link->send_size);
    size = sizeof(message);
#else
    size = link->send_size + 1;
#endif

    ret = isotp_user_send_can(link->send_arbitration_id, message.as.data_array.ptr, size
    #if defined (ISO_TP_USER_SEND_CAN_ARG)
    ,link->user_send_can_arg
    #endif
    );

    return ret;
}

static int isotp_send_first_frame(IsoTpLink* link, uint32_t id) {
    
    IsoTpCanMessage message;
    int ret;

    /* multi frame message length must greater than 7  */
    assert(link->send_size > 7);

    /* setup message  */
    message.as.first_frame.type = ISOTP_PCI_TYPE_FIRST_FRAME;
    message.as.first_frame.FF_DL_low = (uint8_t) link->send_size;
    message.as.first_frame.FF_DL_high = (uint8_t) (0x0F & (link->send_size >> 8));
    (void) memcpy(message.as.first_frame.data, link->send_buffer, sizeof(message.as.first_frame.data));

    /* send message */
    ret = isotp_user_send_can(id, message.as.data_array.ptr, sizeof(message) 
    #if defined (ISO_TP_USER_SEND_CAN_ARG)
    ,link->user_send_can_arg
    #endif

    );
    if (ISOTP_RET_OK == ret) {
        link->send_offset += sizeof(message.as.first_frame.data);
        link->send_sn = 1;
    }

    return ret;
}

static int isotp_send_consecutive_frame(IsoTpLink* link) {
    
    IsoTpCanMessage message;
    uint16_t data_length;
    int ret;
    uint8_t size = 0;

    /* multi frame message length must greater than 7  */
    assert(link->send_size > 7);

    /* setup message  */
    message.as.consecutive_frame.type = TSOTP_PCI_TYPE_CONSECUTIVE_FRAME;
    message.as.consecutive_frame.SN = link->send_sn;
    data_length = link->send_size - link->send_offset;
    if (data_length > sizeof(message.as.consecutive_frame.data)) {
        data_length = sizeof(message.as.consecutive_frame.data);
    }
    (void) memcpy(message.as.consecutive_frame.data, link->send_buffer + link->send_offset, data_length);

    /* send message */
#ifdef ISO_TP_FRAME_PADDING
    (void) memset(message.as.consecutive_frame.data + data_length, ISO_TP_FRAME_PADDING_VALUE, sizeof(message.as.consecutive_frame.data) - data_length);
    size = sizeof(message);
#else
    size = data_length + 1;
#endif

    ret = isotp_user_send_can(link->send_arbitration_id,
            message.as.data_array.ptr, size
#if defined (ISO_TP_USER_SEND_CAN_ARG)
    ,link->user_send_can_arg
#endif
    );

    if (ISOTP_RET_OK == ret) {
        link->send_offset += data_length;
        if (++(link->send_sn) > 0x0F) {
            link->send_sn = 0;
        }
    }
    
    return ret;
}

static int isotp_receive_single_frame(IsoTpLink* link, const IsoTpCanMessage* message, uint8_t len) {
    /* check data length */
    if ((0 == message->as.single_frame.SF_DL) || (message->as.single_frame.SF_DL > (len - 1))) {
        isotp_user_debug("Single-frame length too small.");
        return ISOTP_RET_LENGTH;
    }

    /* copying data */
    (void) memcpy(link->receive_buffer, message->as.single_frame.data, message->as.single_frame.SF_DL);
    link->receive_size = message->as.single_frame.SF_DL;
    
    return ISOTP_RET_OK;
}

static int isotp_receive_first_frame(IsoTpLink *link, IsoTpCanMessage *message, uint8_t len) {
    uint16_t payload_length;

    if (8 != len) {
        isotp_user_debug("First frame should be 8 bytes in length.");
        return ISOTP_RET_LENGTH;
    }

    /* check data length */
    payload_length = message->as.first_frame.FF_DL_high;
    payload_length = (payload_length << 8) + message->as.first_frame.FF_DL_low;

    /* should not use multiple frame transmition */
    if (payload_length <= 7) {
        isotp_user_debug("Should not use multiple frame transmission.");
        return ISOTP_RET_LENGTH;
    }
    
    if (payload_length > link->receive_buf_size) {
        isotp_user_debug("Multi-frame response too large for receiving buffer.");
        return ISOTP_RET_OVERFLOW;
    }
    
    /* copying data */
    (void) memcpy(link->receive_buffer, message->as.first_frame.data, sizeof(message->as.first_frame.data));
    link->receive_size = payload_length;
    link->receive_offset = sizeof(message->as.first_frame.data);
    link->receive_sn = 1;

    return ISOTP_RET_OK;
}

static int isotp_receive_consecutive_frame(IsoTpLink *link, IsoTpCanMessage *message, uint8_t len) {
    uint16_t remaining_bytes;
    
    /* check sn */
    if (link->receive_sn != message->as.consecutive_frame.SN) {
        return ISOTP_RET_WRONG_SN;
    }

    /* check data length */
    remaining_bytes = link->receive_size - link->receive_offset;
    if (remaining_bytes > sizeof(message->as.consecutive_frame.data)) {
        remaining_bytes = sizeof(message->as.consecutive_frame.data);
    }
    if (remaining_bytes > len - 1) {
        isotp_user_debug("Consecutive frame too short.");
        return ISOTP_RET_LENGTH;
    }

    /* copying data */
    (void) memcpy(link->receive_buffer + link->receive_offset, message->as.consecutive_frame.data, remaining_bytes);

    link->receive_offset += remaining_bytes;
    if (++(link->receive_sn) > 0x0F) {
        link->receive_sn = 0;
    }

    return ISOTP_RET_OK;
}

static int isotp_receive_flow_control_frame(IsoTpLink *link, IsoTpCanMessage *message, uint8_t len) {
    /* unused args */
    (void) link;
    (void) message;

    /* check message length */
    if (len < 3) {
        isotp_user_debug("Flow control frame too short.");
        return ISOTP_RET_LENGTH;
    }

    return ISOTP_RET_OK;
}

///////////////////////////////////////////////////////
///                 PUBLIC FUNCTIONS                ///
///////////////////////////////////////////////////////

int isotp_send(IsoTpLink *link, const uint8_t payload[], uint16_t size) {
    return isotp_send_with_id(link, link->send_arbitration_id, payload, size);
}

int isotp_send_with_id(IsoTpLink *link, uint32_t id, const uint8_t payload[], uint16_t size) {
    int ret;

    if (link == 0x0) {
        isotp_user_debug("Link is null!");
        return ISOTP_RET_ERROR;
    }

    if (size > link->send_buf_size) {
        isotp_user_debug("Message size too large. Increase ISO_TP_MAX_MESSAGE_SIZE to set a larger buffer\n");
        char message[128];
        sprintf(&message[0], "Attempted to send %d bytes; max size is %d!\n", size, link->send_buf_size);
        isotp_user_debug(message);
        return ISOTP_RET_OVERFLOW;
    }

    if (ISOTP_SEND_STATUS_INPROGRESS == link->send_status) {
        isotp_user_debug("Abort previous message, transmission in progress.\n");
        return ISOTP_RET_INPROGRESS;
    }

    /* copy into local buffer */
    link->send_size = size;
    link->send_offset = 0;
    (void) memcpy(link->send_buffer, payload, size);

    if (link->send_size < 8) {
        /* send single frame */
        ret = isotp_send_single_frame(link, id);
    } else {
        /* send multi-frame */
        ret = isotp_send_first_frame(link, id);

        /* init multi-frame control flags */
        if (ISOTP_RET_OK == ret) {
            link->send_bs_remain = 0;
            link->send_st_min_us = 0;
            link->send_wtf_count = 0;
            link->send_timer_st = isotp_user_get_us();
            link->send_timer_bs = isotp_user_get_us() + ISO_TP_DEFAULT_RESPONSE_TIMEOUT_US;
            link->send_protocol_result = ISOTP_PROTOCOL_RESULT_OK;
            link->send_status = ISOTP_SEND_STATUS_INPROGRESS;
        }
    }

    return ret;
}

void isotp_on_can_message(IsoTpLink *link, const uint8_t *data, uint8_t len) {
    IsoTpCanMessage message;
    int ret;
    
    if (len < 2 || len > 8) {
        return;
    }

    memcpy(message.as.data_array.ptr, data, len);
    memset(message.as.data_array.ptr + len, 0, sizeof(message.as.data_array.ptr) - len);

    switch (message.as.common.type) {
        case ISOTP_PCI_TYPE_SINGLE: {
            /* update protocol result */
            if (ISOTP_RECEIVE_STATUS_INPROGRESS == link->receive_status) {
                link->receive_protocol_result = ISOTP_PROTOCOL_RESULT_UNEXP_PDU;
            } else {
                link->receive_protocol_result = ISOTP_PROTOCOL_RESULT_OK;
            }

            /* handle message */
            ret = isotp_receive_single_frame(link, &message, len);
            
            if (ISOTP_RET_OK == ret) {
                /* change status */
                link->receive_status = ISOTP_RECEIVE_STATUS_FULL;
            }
            break;
        }
        case ISOTP_PCI_TYPE_FIRST_FRAME: {
            /* update protocol result */
            if (ISOTP_RECEIVE_STATUS_INPROGRESS == link->receive_status) {
                link->receive_protocol_result = ISOTP_PROTOCOL_RESULT_UNEXP_PDU;
            } else {
                link->receive_protocol_result = ISOTP_PROTOCOL_RESULT_OK;
            }

            /* handle message */
            ret = isotp_receive_first_frame(link, &message, len);

            /* if overflow happened */
            if (ISOTP_RET_OVERFLOW == ret) {
                /* update protocol result */
                link->receive_protocol_result = ISOTP_PROTOCOL_RESULT_BUFFER_OVFLW;
                /* change status */
                link->receive_status = ISOTP_RECEIVE_STATUS_IDLE;
                /* send error message */
                isotp_send_flow_control(link, PCI_FLOW_STATUS_OVERFLOW, 0, 0);
                break;
            }

            /* if receive successful */
            if (ISOTP_RET_OK == ret) {
                /* change status */
                link->receive_status = ISOTP_RECEIVE_STATUS_INPROGRESS;
                /* send fc frame */
                link->receive_bs_count = ISO_TP_DEFAULT_BLOCK_SIZE;
                isotp_send_flow_control(link, PCI_FLOW_STATUS_CONTINUE, link->receive_bs_count, ISO_TP_DEFAULT_ST_MIN_US);
                /* refresh timer cs */
                link->receive_timer_cr = isotp_user_get_us() + ISO_TP_DEFAULT_RESPONSE_TIMEOUT_US;
            }
            
            break;
        }
        case TSOTP_PCI_TYPE_CONSECUTIVE_FRAME: {
            /* check if in receiving status */
            if (ISOTP_RECEIVE_STATUS_INPROGRESS != link->receive_status) {
                link->receive_protocol_result = ISOTP_PROTOCOL_RESULT_UNEXP_PDU;
                break;
            }

            /* handle message */
            ret = isotp_receive_consecutive_frame(link, &message, len);

            /* if wrong sn */
            if (ISOTP_RET_WRONG_SN == ret) {
                link->receive_protocol_result = ISOTP_PROTOCOL_RESULT_WRONG_SN;
                link->receive_status = ISOTP_RECEIVE_STATUS_IDLE;
                break;
            }

            /* if success */
            if (ISOTP_RET_OK == ret) {
                /* refresh timer cs */
                link->receive_timer_cr = isotp_user_get_us() + ISO_TP_DEFAULT_RESPONSE_TIMEOUT_US;
                
                /* receive finished */
                if (link->receive_offset >= link->receive_size) {
                    link->receive_status = ISOTP_RECEIVE_STATUS_FULL;
                } else {
                    /* send fc when bs reaches limit */
                    if (0 == --link->receive_bs_count) {
                        link->receive_bs_count = ISO_TP_DEFAULT_BLOCK_SIZE;
                        isotp_send_flow_control(link, PCI_FLOW_STATUS_CONTINUE, link->receive_bs_count, ISO_TP_DEFAULT_ST_MIN_US);
                    }
                }
            }
            
            break;
        }
        case ISOTP_PCI_TYPE_FLOW_CONTROL_FRAME:
            /* handle fc frame only when sending in progress  */
            if (ISOTP_SEND_STATUS_INPROGRESS != link->send_status) {
                break;
            }

            /* handle message */
            ret = isotp_receive_flow_control_frame(link, &message, len);
            
            if (ISOTP_RET_OK == ret) {
                /* refresh bs timer */
                link->send_timer_bs = isotp_user_get_us() + ISO_TP_DEFAULT_RESPONSE_TIMEOUT_US;

                /* overflow */
                if (PCI_FLOW_STATUS_OVERFLOW == message.as.flow_control.FS) {
                    link->send_protocol_result = ISOTP_PROTOCOL_RESULT_BUFFER_OVFLW;
                    link->send_status = ISOTP_SEND_STATUS_ERROR;
                }

                /* wait */
                else if (PCI_FLOW_STATUS_WAIT == message.as.flow_control.FS) {
                    link->send_wtf_count += 1;
                    /* wait exceed allowed count */
                    if (link->send_wtf_count > ISO_TP_MAX_WFT_NUMBER) {
                        link->send_protocol_result = ISOTP_PROTOCOL_RESULT_WFT_OVRN;
                        link->send_status = ISOTP_SEND_STATUS_ERROR;
                    }
                }

                /* permit send */
                else if (PCI_FLOW_STATUS_CONTINUE == message.as.flow_control.FS) {
                    if (0 == message.as.flow_control.BS) {
                        link->send_bs_remain = ISOTP_INVALID_BS;
                    } else {
                        link->send_bs_remain = message.as.flow_control.BS;
                    }
                    uint32_t message_st_min_us = isotp_st_min_to_us(message.as.flow_control.STmin);
                    link->send_st_min_us = message_st_min_us > ISO_TP_DEFAULT_ST_MIN_US ? message_st_min_us : ISO_TP_DEFAULT_ST_MIN_US; // prefer as much st_min as possible for stability?
                    link->send_wtf_count = 0;
                }
            }
            break;
        default:
            break;
    };
    
    return;
}

int isotp_receive(IsoTpLink *link, uint8_t *payload, const uint16_t payload_size, uint16_t *out_size) {
    uint16_t copylen;
    
    if (ISOTP_RECEIVE_STATUS_FULL != link->receive_status) {
        return ISOTP_RET_NO_DATA;
    }

    copylen = link->receive_size;
    if (copylen > payload_size) {
        copylen = payload_size;
    }

    memcpy(payload, link->receive_buffer, copylen);
    *out_size = copylen;

    link->receive_status = ISOTP_RECEIVE_STATUS_IDLE;

    return ISOTP_RET_OK;
}

void isotp_init_link(IsoTpLink *link, uint32_t sendid, uint8_t *sendbuf, uint16_t sendbufsize, uint8_t *recvbuf, uint16_t recvbufsize) {
    memset(link, 0, sizeof(*link));
    link->receive_status = ISOTP_RECEIVE_STATUS_IDLE;
    link->send_status = ISOTP_SEND_STATUS_IDLE;
    link->send_arbitration_id = sendid;
    link->send_buffer = sendbuf;
    link->send_buf_size = sendbufsize;
    link->receive_buffer = recvbuf;
    link->receive_buf_size = recvbufsize;
    
    return;
}

void isotp_poll(IsoTpLink *link) {
    int ret;

    /* only polling when operation in progress */
    if (ISOTP_SEND_STATUS_INPROGRESS == link->send_status) {

        /* continue send data */
        if (/* send data if bs_remain is invalid or bs_remain large than zero */
        (ISOTP_INVALID_BS == link->send_bs_remain || link->send_bs_remain > 0) &&
        /* and if st_min is zero or go beyond interval time */
        (0 == link->send_st_min_us || IsoTpTimeAfter(isotp_user_get_us(), link->send_timer_st))) {
            
            ret = isotp_send_consecutive_frame(link);
            if (ISOTP_RET_OK == ret) {
                if (ISOTP_INVALID_BS != link->send_bs_remain) {
                    link->send_bs_remain -= 1;
                }
                link->send_timer_bs = isotp_user_get_us() + ISO_TP_DEFAULT_RESPONSE_TIMEOUT_US;
                link->send_timer_st = isotp_user_get_us() + link->send_st_min_us;

                /* check if send finish */
                if (link->send_offset >= link->send_size) {
                    link->send_status = ISOTP_SEND_STATUS_IDLE;
                }
            } else if (ISOTP_RET_NOSPACE == ret) {
                /* shim reported that it isn't able to send a frame at present, retry on next call */
            } else {
                link->send_status = ISOTP_SEND_STATUS_ERROR;
            }
        }

        /* check timeout */
        if (IsoTpTimeAfter(isotp_user_get_us(), link->send_timer_bs)) {
            link->send_protocol_result = ISOTP_PROTOCOL_RESULT_TIMEOUT_BS;
            link->send_status = ISOTP_SEND_STATUS_ERROR;
        }
    }

    /* only polling when operation in progress */
    if (ISOTP_RECEIVE_STATUS_INPROGRESS == link->receive_status) {
        
        /* check timeout */
        if (IsoTpTimeAfter(isotp_user_get_us(), link->receive_timer_cr)) {
            link->receive_protocol_result = ISOTP_PROTOCOL_RESULT_TIMEOUT_CR;
            link->receive_status = ISOTP_RECEIVE_STATUS_IDLE;
        }
    }

    return;
}
#endif

