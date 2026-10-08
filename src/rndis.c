/*
 * rndis.c —— RNDIS over USB（自定义 TinyUSB 类驱动实现）
 *
 * 接口类码使用 TinyUSB 的 TUD_RNDIS_ITF_*（0xE0/01/03，Windows 7+ 布局），
 * 配合 usb_desc.c 里的 TUD_RNDIS_DESCRIPTOR 描述符。
 *
 * 控制面：SEND_ENCAPSULATED_COMMAND(OUT) / GET_ENCAPSULATED_RESPONSE(IN)
 * 数据面：REMOTE_NDIS_PACKET_MSG 封装的以太网帧（一对 bulk 端点）
 * 通知面：interrupt IN 端点发送 RESPONSE_AVAILABLE / INDICATE_STATUS
 *
 * 所有报文字段都用字节序辅助函数读写，避免非对齐访问（Xtensa 不允许非对齐 32 位访问）。
 */
#include "rndis.h"

#include <string.h>

#include "esp_log.h"

#include "device/usbd_pvt.h"
#include "tusb.h"

#include "usb_net.h"

static const char *TAG = "rndis";

/* ───────────── RNDIS 常量 ───────────── */

#define RNDIS_MSG_PACKET            0x00000001u
#define RNDIS_MSG_INITIALIZE        0x00000002u
#define RNDIS_MSG_HALT              0x00000003u
#define RNDIS_MSG_QUERY             0x00000004u
#define RNDIS_MSG_SET               0x00000005u
#define RNDIS_MSG_RESET             0x00000006u
#define RNDIS_MSG_INDICATE_STATUS   0x00000007u
#define RNDIS_MSG_KEEPALIVE         0x00000008u
#define RNDIS_MSG_CMPLT_FLAG        0x80000000u

#define RNDIS_STATUS_SUCCESS        0x00000000u
#define RNDIS_STATUS_FAILURE        0xC0000001u
#define RNDIS_STATUS_NOT_SUPPORTED  0xC00000BBu
#define RNDIS_STATUS_MEDIA_CONNECT  0x4001000Bu

/* OID */
#define OID_GEN_SUPPORTED_LIST        0x00010101u
#define OID_GEN_HARDWARE_STATUS       0x00010102u
#define OID_GEN_MEDIA_SUPPORTED       0x00010103u
#define OID_GEN_MEDIA_IN_USE          0x00010104u
#define OID_GEN_MAXIMUM_FRAME_SIZE    0x00010106u
#define OID_GEN_LINK_SPEED            0x00010107u
#define OID_GEN_TRANSMIT_BLOCK_SIZE   0x0001010Au
#define OID_GEN_RECEIVE_BLOCK_SIZE    0x0001010Bu
#define OID_GEN_VENDOR_ID             0x0001010Cu
#define OID_GEN_VENDOR_DESCRIPTION    0x0001010Du
#define OID_GEN_CURRENT_PACKET_FILTER 0x0001010Eu
#define OID_GEN_MAXIMUM_TOTAL_SIZE    0x00010111u
#define OID_GEN_MEDIA_CONNECT_STATUS  0x00010114u
#define OID_GEN_MAXIMUM_SEND_PACKETS  0x00010115u
#define OID_802_3_PERMANENT_ADDRESS   0x01010101u
#define OID_802_3_CURRENT_ADDRESS     0x01010102u
#define OID_802_3_MULTICAST_LIST      0x01010103u
#define OID_802_3_MAXIMUM_LIST_SIZE   0x01010104u

/* 报文头长度（字节） */
#define RNDIS_MSG_HDR_LEN           8u    /* MessageType + MessageLength */
#define RNDIS_PACKET_HDR_LEN        44u   /* REMOTE_NDIS_PACKET_MSG 头 */
#define RNDIS_PACKET_DATA_OFFSET    36u   /* DataOffset 相对 DataOffset 字段 */
#define RNDIS_QUERY_CMPLT_HDR_LEN   24u
#define RNDIS_SET_CMPLT_HDR_LEN     16u
#define RNDIS_INIT_CMPLT_LEN        52u
#define RNDIS_RESET_CMPLT_LEN       16u
#define RNDIS_KEEPALIVE_CMPLT_LEN   16u
#define RNDIS_INDICATE_STATUS_LEN   20u

#define RNDIS_MTU                   1514u
#define RNDIS_MAX_XFER              0x4000u

#define RNDIS_CTRL_BUF_SIZE         256u
#define RNDIS_RX_BUF_SIZE           (RNDIS_PACKET_HDR_LEN + RNDIS_MTU)
#define RNDIS_TX_BUF_SIZE           (RNDIS_PACKET_HDR_LEN + RNDIS_MTU)

/* ───────────── 字节序辅助（避免非对齐访问） ───────────── */

static inline uint32_t rd_u32(const uint8_t *p)
{
    return (uint32_t) p[0] | ((uint32_t) p[1] << 8) | ((uint32_t) p[2] << 16) | ((uint32_t) p[3] << 24);
}

static inline void wr_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
    p[2] = (uint8_t)((v >> 16) & 0xff);
    p[3] = (uint8_t)((v >> 24) & 0xff);
}

/* ───────────── 状态 ───────────── */

typedef struct {
    uint8_t rhport;
    uint8_t itf_num;      /* 控制接口号 */
    uint8_t ep_notif;
    uint8_t ep_in;
    uint8_t ep_out;
    uint16_t ep_size;
    bool opened;
    bool initialized;     /* 主机完成 REMOTE_NDIS_INITIALIZE */
    uint32_t packet_filter;
    uint8_t mac[6];
} rndis_state_t;

static rndis_state_t s_rndis;
static bool s_can_xmit = true;

/* 控制面缓冲：命令与应答共用（主机读取完才会发下一条命令） */
static uint8_t s_ctrl_buf[RNDIS_CTRL_BUF_SIZE];
/* 通知端点缓冲 */
static uint8_t s_notif_buf[RNDIS_INDICATE_STATUS_LEN];
/* 数据面缓冲（必须位于内部 RAM，供 DMA 使用） */
static uint8_t s_rx_buf[RNDIS_RX_BUF_SIZE];
static uint8_t s_tx_buf[RNDIS_TX_BUF_SIZE];

/* ───────────── 端点辅助 ───────────── */

static bool do_in_xfer(const uint8_t *buf, uint16_t len)
{
    if (s_rndis.ep_in == 0) {
        return false;
    }
    if (!usbd_edpt_claim(s_rndis.rhport, s_rndis.ep_in)) {
        return false;
    }
    if (len) {
        memcpy(s_tx_buf, buf, len);
    }
    if (!usbd_edpt_xfer(s_rndis.rhport, s_rndis.ep_in, s_tx_buf, len, false)) {
        usbd_edpt_release(s_rndis.rhport, s_rndis.ep_in);
        return false;
    }
    return true;
}

static void rndis_rx_arm(void)
{
    if (s_rndis.ep_out == 0) {
        return;
    }
    if (!usbd_edpt_claim(s_rndis.rhport, s_rndis.ep_out)) {
        return;
    }
    if (!usbd_edpt_xfer(s_rndis.rhport, s_rndis.ep_out, s_rx_buf, sizeof(s_rx_buf), false)) {
        usbd_edpt_release(s_rndis.rhport, s_rndis.ep_out);
    }
}

static void rndis_notify(const uint8_t *data, uint16_t len)
{
    if (s_rndis.ep_notif == 0 || len > sizeof(s_notif_buf)) {
        return;
    }
    if (!usbd_edpt_claim(s_rndis.rhport, s_rndis.ep_notif)) {
        return;
    }
    memcpy(s_notif_buf, data, len);
    if (!usbd_edpt_xfer(s_rndis.rhport, s_rndis.ep_notif, s_notif_buf, len, false)) {
        usbd_edpt_release(s_rndis.rhport, s_rndis.ep_notif);
    }
}

/* RESPONSE_AVAILABLE 通知（8 字节） */
static void notify_response_available(void)
{
    uint8_t notif[8] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    rndis_notify(notif, sizeof(notif));
}

/* REMOTE_NDIS_INDICATE_STATUS_MSG（媒体已连接） */
static void indicate_status(uint32_t status)
{
    uint8_t buf[RNDIS_INDICATE_STATUS_LEN] = {0};
    wr_u32(buf + 0, RNDIS_MSG_INDICATE_STATUS);
    wr_u32(buf + 4, RNDIS_INDICATE_STATUS_LEN);
    wr_u32(buf + 8, status);
    wr_u32(buf + 12, 0);   /* StatusBufferLength */
    wr_u32(buf + 16, 0);   /* StatusBufferOffset */
    rndis_notify(buf, sizeof(buf));
}

/* ───────────── OID 处理 ───────────── */

static const uint32_t s_supported_oids[] = {
    OID_GEN_SUPPORTED_LIST,
    OID_GEN_HARDWARE_STATUS,
    OID_GEN_MEDIA_SUPPORTED,
    OID_GEN_MEDIA_IN_USE,
    OID_GEN_MAXIMUM_FRAME_SIZE,
    OID_GEN_LINK_SPEED,
    OID_GEN_TRANSMIT_BLOCK_SIZE,
    OID_GEN_RECEIVE_BLOCK_SIZE,
    OID_GEN_VENDOR_ID,
    OID_GEN_VENDOR_DESCRIPTION,
    OID_GEN_CURRENT_PACKET_FILTER,
    OID_GEN_MAXIMUM_TOTAL_SIZE,
    OID_GEN_MEDIA_CONNECT_STATUS,
    OID_GEN_MAXIMUM_SEND_PACKETS,
    OID_802_3_PERMANENT_ADDRESS,
    OID_802_3_CURRENT_ADDRESS,
    OID_802_3_MULTICAST_LIST,
    OID_802_3_MAXIMUM_LIST_SIZE,
};

static const char s_vendor_desc[] = "KeyVault USB RNDIS";

/* 查询：返回数据长度（0 表示不支持），data 长度上限 RNDIS_CTRL_BUF_SIZE - 头部 */
static uint16_t oid_query(uint32_t oid, uint8_t *data, uint16_t max_len)
{
    uint16_t len = 0;

    switch (oid) {
    case OID_GEN_SUPPORTED_LIST:
        len = (uint16_t) sizeof(s_supported_oids);
        if (len > max_len) {
            return 0;
        }
        memcpy(data, s_supported_oids, len);
        break;
    case OID_GEN_HARDWARE_STATUS:   /* NdisHardwareStatusReady */
        wr_u32(data, 0);
        len = 4;
        break;
    case OID_GEN_MEDIA_SUPPORTED:
    case OID_GEN_MEDIA_IN_USE:      /* NdisMedium802_3 */
        wr_u32(data, 0);
        len = 4;
        break;
    case OID_GEN_MAXIMUM_FRAME_SIZE:
        wr_u32(data, RNDIS_MTU);
        len = 4;
        break;
    case OID_GEN_LINK_SPEED:        /* 单位 100bps：12Mbps */
        wr_u32(data, 120000);
        len = 4;
        break;
    case OID_GEN_TRANSMIT_BLOCK_SIZE:
    case OID_GEN_RECEIVE_BLOCK_SIZE:
        wr_u32(data, RNDIS_MTU);
        len = 4;
        break;
    case OID_GEN_VENDOR_ID:
        wr_u32(data, 0x00000001);
        len = 4;
        break;
    case OID_GEN_VENDOR_DESCRIPTION:
        len = (uint16_t) strlen(s_vendor_desc) + 1;
        if (len > max_len) {
            return 0;
        }
        memcpy(data, s_vendor_desc, len);
        break;
    case OID_GEN_CURRENT_PACKET_FILTER:
        wr_u32(data, s_rndis.packet_filter);
        len = 4;
        break;
    case OID_GEN_MAXIMUM_TOTAL_SIZE:
        wr_u32(data, RNDIS_MTU + RNDIS_PACKET_HDR_LEN);
        len = 4;
        break;
    case OID_GEN_MEDIA_CONNECT_STATUS:  /* NdisMediaStateConnected */
        wr_u32(data, 0);
        len = 4;
        break;
    case OID_GEN_MAXIMUM_SEND_PACKETS:
        wr_u32(data, 1);
        len = 4;
        break;
    case OID_802_3_PERMANENT_ADDRESS:
    case OID_802_3_CURRENT_ADDRESS:
        memcpy(data, s_rndis.mac, 6);
        len = 6;
        break;
    case OID_802_3_MULTICAST_LIST:
        len = 0;
        break;
    case OID_802_3_MAXIMUM_LIST_SIZE:
        wr_u32(data, 1);
        len = 4;
        break;
    default:
        return 0;
    }

    return len;
}

static uint32_t oid_set(uint32_t oid, const uint8_t *data, uint16_t len)
{
    switch (oid) {
    case OID_GEN_CURRENT_PACKET_FILTER:
        if (len < 4) {
            return RNDIS_STATUS_FAILURE;
        }
        s_rndis.packet_filter = rd_u32(data);
        return RNDIS_STATUS_SUCCESS;
    case OID_802_3_MULTICAST_LIST:
        /* 不维护多播表，直接接受 */
        return RNDIS_STATUS_SUCCESS;
    default:
        return RNDIS_STATUS_NOT_SUPPORTED;
    }
}

/* ───────────── 命令处理 ───────────── */

static void handle_command(const uint8_t *cmd, uint16_t len)
{
    if (len < RNDIS_MSG_HDR_LEN) {
        return;
    }

    uint32_t msg_type = rd_u32(cmd);
    uint32_t req_id = (len >= 12) ? rd_u32(cmd + 8) : 0;

    switch (msg_type) {
    case RNDIS_MSG_INITIALIZE: {
        /* INITIALIZE_MSG: Type, Length, RequestId, MajorVersion, MinorVersion, MaxTransferSize */
        uint32_t major = (len >= 16) ? rd_u32(cmd + 12) : 1;
        uint32_t minor = (len >= 20) ? rd_u32(cmd + 16) : 0;
        uint32_t max_xfer = (len >= 24) ? rd_u32(cmd + 20) : RNDIS_MAX_XFER;
        if (max_xfer == 0 || max_xfer > RNDIS_MAX_XFER) {
            max_xfer = RNDIS_MAX_XFER;
        }

        memset(s_ctrl_buf, 0, RNDIS_INIT_CMPLT_LEN);
        wr_u32(s_ctrl_buf + 0, RNDIS_MSG_INITIALIZE | RNDIS_MSG_CMPLT_FLAG);
        wr_u32(s_ctrl_buf + 4, RNDIS_INIT_CMPLT_LEN);
        wr_u32(s_ctrl_buf + 8, req_id);
        wr_u32(s_ctrl_buf + 12, RNDIS_STATUS_SUCCESS);
        wr_u32(s_ctrl_buf + 16, major);
        wr_u32(s_ctrl_buf + 20, minor);
        wr_u32(s_ctrl_buf + 24, 0x00000001);        /* DeviceFlags: 支持多包/单包均可 */
        wr_u32(s_ctrl_buf + 28, 0x00000000);        /* Medium: 802.3 */
        wr_u32(s_ctrl_buf + 32, 1);                 /* MaxPacketsPerTransfer */
        wr_u32(s_ctrl_buf + 36, max_xfer);
        wr_u32(s_ctrl_buf + 40, 3);                 /* PacketAlignmentFactor */
        wr_u32(s_ctrl_buf + 44, 0);                 /* AfListOffset */
        wr_u32(s_ctrl_buf + 48, 0);                 /* AfListSize */

        s_rndis.initialized = true;
        s_can_xmit = true;
        usb_net_port_set_link(USB_NET_PORT_RNDIS, true);
        ESP_LOGI(TAG, "RNDIS 初始化完成（v%u.%u, MTU=%u）", (unsigned)major, (unsigned)minor, (unsigned)RNDIS_MTU);
        break;
    }

    case RNDIS_MSG_QUERY: {
        /* QUERY_MSG: Type, Length, RequestId, OID, InfoBufLen, InfoBufOffset, DeviceVcHandle */
        uint32_t oid = (len >= 16) ? rd_u32(cmd + 12) : 0;
        uint16_t max_data = (uint16_t)(RNDIS_CTRL_BUF_SIZE - RNDIS_QUERY_CMPLT_HDR_LEN);
        uint16_t data_len = oid_query(oid, s_ctrl_buf + RNDIS_QUERY_CMPLT_HDR_LEN, max_data);
        uint32_t status = RNDIS_STATUS_SUCCESS;
        if (data_len == 0) {
            status = RNDIS_STATUS_NOT_SUPPORTED;
        }

        wr_u32(s_ctrl_buf + 0, RNDIS_MSG_QUERY | RNDIS_MSG_CMPLT_FLAG);
        wr_u32(s_ctrl_buf + 4, RNDIS_QUERY_CMPLT_HDR_LEN + data_len);
        wr_u32(s_ctrl_buf + 8, req_id);
        wr_u32(s_ctrl_buf + 12, status);
        wr_u32(s_ctrl_buf + 16, data_len);
        wr_u32(s_ctrl_buf + 20, RNDIS_QUERY_CMPLT_HDR_LEN - 8);  /* 相对 RequestId 字段 */
        break;
    }

    case RNDIS_MSG_SET: {
        uint32_t oid = (len >= 16) ? rd_u32(cmd + 12) : 0;
        uint32_t buf_len = (len >= 20) ? rd_u32(cmd + 16) : 0;
        uint32_t buf_off = (len >= 24) ? rd_u32(cmd + 20) : 0;
        const uint8_t *src = cmd + 8 + buf_off;     /* 相对 RequestId 字段 */
        if (buf_len > len || (8 + buf_off + buf_len) > len) {
            buf_len = 0;
        }
        uint32_t status = oid_set(oid, src, (uint16_t) buf_len);

        wr_u32(s_ctrl_buf + 0, RNDIS_MSG_SET | RNDIS_MSG_CMPLT_FLAG);
        wr_u32(s_ctrl_buf + 4, RNDIS_SET_CMPLT_HDR_LEN);
        wr_u32(s_ctrl_buf + 8, req_id);
        wr_u32(s_ctrl_buf + 12, status);
        break;
    }

    case RNDIS_MSG_RESET:
        memset(s_ctrl_buf, 0, RNDIS_RESET_CMPLT_LEN);
        wr_u32(s_ctrl_buf + 0, RNDIS_MSG_RESET | RNDIS_MSG_CMPLT_FLAG);
        wr_u32(s_ctrl_buf + 4, RNDIS_RESET_CMPLT_LEN);
        wr_u32(s_ctrl_buf + 8, RNDIS_STATUS_SUCCESS);
        wr_u32(s_ctrl_buf + 12, 0);                 /* AddressingReset */
        s_rndis.packet_filter = 0;
        break;

    case RNDIS_MSG_KEEPALIVE:
        wr_u32(s_ctrl_buf + 0, RNDIS_MSG_KEEPALIVE | RNDIS_MSG_CMPLT_FLAG);
        wr_u32(s_ctrl_buf + 4, RNDIS_KEEPALIVE_CMPLT_LEN);
        wr_u32(s_ctrl_buf + 8, req_id);
        wr_u32(s_ctrl_buf + 12, RNDIS_STATUS_SUCCESS);
        break;

    case RNDIS_MSG_HALT:
        s_rndis.initialized = false;
        usb_net_port_set_link(USB_NET_PORT_RNDIS, false);
        ESP_LOGI(TAG, "主机请求 RNDIS HALT");
        return;                                     /* HALT 无应答 */

    default:
        ESP_LOGW(TAG, "未支持的 RNDIS 消息: 0x%08X", (unsigned)msg_type);
        return;
    }

    notify_response_available();
}

/* ───────────── 数据面 ───────────── */

static void handle_packet(uint32_t len)
{
    if (len < RNDIS_PACKET_HDR_LEN) {
        return;
    }
    if (rd_u32(s_rx_buf) != RNDIS_MSG_PACKET) {
        return;
    }

    uint32_t data_off = rd_u32(s_rx_buf + 8);
    uint32_t data_len = rd_u32(s_rx_buf + 12);
    uint32_t start = 8 + data_off;                  /* DataOffset 相对 DataOffset 字段 */
    if (data_len == 0 || data_len > RNDIS_MTU || (start + data_len) > len) {
        return;
    }

    usb_net_port_rx(USB_NET_PORT_RNDIS, s_rx_buf + start, (uint16_t) data_len, NULL);
}

/* ───────────── 类驱动实现 ───────────── */

static void rndisd_init(void)
{
    memset(&s_rndis, 0, sizeof(s_rndis));
    s_can_xmit = true;
}

static void rndisd_reset(uint8_t rhport)
{
    (void) rhport;
    uint8_t mac[6];
    memcpy(mac, s_rndis.mac, sizeof(mac));
    rndisd_init();
    memcpy(s_rndis.mac, mac, sizeof(mac));
    usb_net_port_set_link(USB_NET_PORT_RNDIS, false);
}

static uint16_t rndisd_open(uint8_t rhport, tusb_desc_interface_t const *itf_desc, uint16_t max_len)
{
    /* 接管 RNDIS 控制接口：支持 Windows 10/11 原生驱动匹配的 0xEF/0x04/0x01，以及传统 0xE0/0x01/0x03 */
    bool is_rndis = (itf_desc->bInterfaceClass == 0xEF && itf_desc->bInterfaceSubClass == 0x04 && itf_desc->bInterfaceProtocol == 0x01) ||
                    (itf_desc->bInterfaceClass == TUD_RNDIS_ITF_CLASS && itf_desc->bInterfaceSubClass == TUD_RNDIS_ITF_SUBCLASS && itf_desc->bInterfaceProtocol == TUD_RNDIS_ITF_PROTOCOL);
    if (!is_rndis) {
        return 0;
    }

    uint16_t drv_len = sizeof(tusb_desc_interface_t);
    uint8_t const *p_desc = tu_desc_next(itf_desc);
    uint8_t const *desc_end = p_desc + max_len;

    s_rndis.rhport = rhport;
    s_rndis.itf_num = itf_desc->bInterfaceNumber;

    /* 功能描述符 */
    while (tu_desc_in_bounds(p_desc, desc_end) && TUSB_DESC_CS_INTERFACE == tu_desc_type(p_desc)) {
        drv_len += tu_desc_len(p_desc);
        p_desc = tu_desc_next(p_desc);
    }

    /* 通知端点（interrupt IN） */
    if (tu_desc_in_bounds(p_desc, desc_end) && TUSB_DESC_ENDPOINT == tu_desc_type(p_desc)) {
        TU_ASSERT(usbd_edpt_open(rhport, (tusb_desc_endpoint_t const *) p_desc), 0);
        s_rndis.ep_notif = ((tusb_desc_endpoint_t const *) p_desc)->bEndpointAddress;
        drv_len += tu_desc_len(p_desc);
        p_desc = tu_desc_next(p_desc);
    }

    /* 数据接口 */
    TU_ASSERT(tu_desc_in_bounds(p_desc, desc_end) && TUSB_DESC_INTERFACE == tu_desc_type(p_desc), 0);
    drv_len += tu_desc_len(p_desc);
    p_desc = tu_desc_next(p_desc);

    /* 一对 bulk 端点 */
    TU_ASSERT(tu_desc_in_bounds(p_desc, desc_end) && TUSB_DESC_ENDPOINT == tu_desc_type(p_desc), 0);
    s_rndis.ep_size = tu_edpt_packet_size((tusb_desc_endpoint_t const *) p_desc);
    TU_ASSERT(usbd_open_edpt_pair(rhport, p_desc, 2, TUSB_XFER_BULK, &s_rndis.ep_out, &s_rndis.ep_in), 0);
    drv_len += 2 * sizeof(tusb_desc_endpoint_t);

    s_rndis.opened = true;
    s_rndis.initialized = false;
    s_rndis.packet_filter = 0;
    s_can_xmit = true;

    /* 准备接收 */
    rndis_rx_arm();

    ESP_LOGI(TAG, "RNDIS 接口就绪 itf=%u notif=0x%02X out=0x%02X in=0x%02X",
             s_rndis.itf_num, s_rndis.ep_notif, s_rndis.ep_out, s_rndis.ep_in);
    return drv_len;
}

static bool rndisd_control_xfer_cb(uint8_t rhport, uint8_t stage, tusb_control_request_t const *request)
{
    if (stage == CONTROL_STAGE_SETUP) {
        if (request->bmRequestType_bit.type != TUSB_REQ_TYPE_CLASS) {
            return false;
        }
        if (request->wIndex != s_rndis.itf_num) {
            return false;
        }

        if (request->bmRequestType_bit.direction == TUSB_DIR_OUT) {
            /* SEND_ENCAPSULATED_COMMAND */
            return tud_control_xfer(rhport, request, s_ctrl_buf, sizeof(s_ctrl_buf));
        }

        /* GET_ENCAPSULATED_RESPONSE */
        uint32_t msglen = rd_u32(s_ctrl_buf + 4);
        if (msglen < RNDIS_MSG_HDR_LEN || msglen > sizeof(s_ctrl_buf)) {
            msglen = RNDIS_MSG_HDR_LEN;
        }
        return tud_control_xfer(rhport, request, s_ctrl_buf, (uint16_t) msglen);
    } else if (stage == CONTROL_STAGE_DATA) {
        if (request->bmRequestType_bit.type == TUSB_REQ_TYPE_CLASS &&
            request->bmRequestType_bit.direction == TUSB_DIR_OUT &&
            request->wIndex == s_rndis.itf_num) {
            handle_command(s_ctrl_buf, request->wLength);

            /* 初始化完成后主动通告链路已连接，帮助主机尽快进入数据阶段 */
            if (s_rndis.initialized) {
                indicate_status(RNDIS_STATUS_MEDIA_CONNECT);
            }
        }
    }

    return true;
}

static bool rndisd_xfer_cb(uint8_t rhport, uint8_t ep_addr, xfer_result_t result, uint32_t xferred_bytes)
{
    (void) rhport;
    (void) result;

    if (ep_addr == s_rndis.ep_out) {
        handle_packet(xferred_bytes);
        rndis_rx_arm();
    } else if (ep_addr == s_rndis.ep_in) {
        /* TinyUSB 要求类驱动自行处理 ZLP */
        if (xferred_bytes > 0 && 0 == (xferred_bytes & (s_rndis.ep_size - 1))) {
            do_in_xfer(NULL, 0);
        } else {
            s_can_xmit = true;
        }
    }

    return true;
}

static const usbd_class_driver_t s_rndis_driver = {
    .name            = "RNDIS",
    .init            = rndisd_init,
    .deinit          = NULL,
    .reset           = rndisd_reset,
    .open            = rndisd_open,
    .control_xfer_cb = rndisd_control_xfer_cb,
    .xfer_cb         = rndisd_xfer_cb,
    .xfer_isr        = NULL,
    .sof             = NULL,
};

/* TinyUSB 扩展点：注册自定义类驱动（数组必须在协议栈运行期间保持有效） */
usbd_class_driver_t const *usbd_app_driver_get_cb(uint8_t *driver_count)
{
    *driver_count = 1;
    return &s_rndis_driver;
}

/* ───────────── 对外接口 ───────────── */

void rndis_init(const uint8_t mac[6])
{
    memcpy(s_rndis.mac, mac, sizeof(s_rndis.mac));
}

bool rndis_is_ready(void)
{
    return s_rndis.opened && s_rndis.initialized;
}

bool rndis_xmit(const void *frame, uint16_t len)
{
    if (!rndis_is_ready() || len == 0 || len > RNDIS_MTU) {
        return false;
    }
    if (!s_can_xmit) {
        return false;
    }

    memset(s_tx_buf, 0, RNDIS_PACKET_HDR_LEN);
    wr_u32(s_tx_buf + 0, RNDIS_MSG_PACKET);
    wr_u32(s_tx_buf + 4, RNDIS_PACKET_HDR_LEN + len);
    wr_u32(s_tx_buf + 8, RNDIS_PACKET_DATA_OFFSET);
    wr_u32(s_tx_buf + 12, len);
    memcpy(s_tx_buf + RNDIS_PACKET_HDR_LEN, frame, len);

    if (!usbd_edpt_claim(s_rndis.rhport, s_rndis.ep_in)) {
        return false;
    }
    if (!usbd_edpt_xfer(s_rndis.rhport, s_rndis.ep_in, s_tx_buf, RNDIS_PACKET_HDR_LEN + len, false)) {
        usbd_edpt_release(s_rndis.rhport, s_rndis.ep_in);
        return false;
    }
    s_can_xmit = false;
    return true;
}
