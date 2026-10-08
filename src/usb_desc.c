/*
 * usb_desc.c —— USB 原生 RNDIS + HID 复合设备描述符
 *
 * 暴露 RNDIS 网络设备（接口 0 & 1）与 HID 键盘设备（接口 2）。
 * 采用 Windows 10/11 原生驱动匹配的 Class 0xEF / SubClass 0x04 / Protocol 0x01，
 * 同时保留 EP3-IN 用于免驱 USB 键盘物理击键输入。
 */
#include "usb_desc.h"

#include <stdio.h>
#include <string.h>
#include "class/hid/hid_device.h"

/* ── 接口编号 ── */
enum {
    ITF_NUM_RNDIS = 0,
    ITF_NUM_RNDIS_DATA,
    ITF_NUM_HID,
    ITF_NUM_TOTAL
};

/* ── 端点地址（IN/OUT 独立编号） ── */
enum {
    EPNUM_RNDIS_NOTIF = 0x81,
    EPNUM_RNDIS_OUT   = 0x02,
    EPNUM_RNDIS_IN    = 0x82,
    EPNUM_HID         = 0x83,
};

/* ── 字符串索引 ── */
enum {
    STRID_LANGID = 0,
    STRID_MANUFACTURER,
    STRID_PRODUCT,
    STRID_SERIAL,
    STRID_RNDIS_INTERFACE,    /* 4 */
    STRID_HID_INTERFACE,      /* 5 */
    STRID_COUNT
};

/* Microsoft Windows 10/11 inbox RNDIS 描述符模板 (Class 0xEF, SubClass 0x04, Protocol 0x01)
 * 对应 Windows 原生驱动匹配规则：%RndisDevice% = RNDIS.NT.6.0, USB\Class_EF&SubClass_04&Prot_01 */
#define KEYVAULT_RNDIS_DESC_LEN  (8+9+5+5+4+5+7+9+7+7)

#define KEYVAULT_RNDIS_DESCRIPTOR(_itfnum, _stridx, _ep_notif, _ep_notif_size, _epout, _epin, _epsize) \
  /* Interface Association */\
  8, TUSB_DESC_INTERFACE_ASSOCIATION, _itfnum, 2, 0xEF, 0x04, 0x01, 0,\
  /* CDC Control Interface */\
  9, TUSB_DESC_INTERFACE, _itfnum, 0, 1, 0xEF, 0x04, 0x01, _stridx,\
  /* CDC-ACM Header */\
  5, TUSB_DESC_CS_INTERFACE, CDC_FUNC_DESC_HEADER, U16_TO_U8S_LE(0x0110),\
  /* CDC Call Management */\
  5, TUSB_DESC_CS_INTERFACE, CDC_FUNC_DESC_CALL_MANAGEMENT, 0, (uint8_t)((_itfnum) + 1),\
  /* ACM */\
  4, TUSB_DESC_CS_INTERFACE, CDC_FUNC_DESC_ABSTRACT_CONTROL_MANAGEMENT, 0,\
  /* CDC Union */\
  5, TUSB_DESC_CS_INTERFACE, CDC_FUNC_DESC_UNION, _itfnum, (uint8_t)((_itfnum) + 1),\
  /* Endpoint Notification */\
  7, TUSB_DESC_ENDPOINT, _ep_notif, TUSB_XFER_INTERRUPT, U16_TO_U8S_LE(_ep_notif_size), 1,\
  /* CDC Data Interface */\
  9, TUSB_DESC_INTERFACE, (uint8_t)((_itfnum)+1), 0, 2, TUSB_CLASS_CDC_DATA, 0, 0, 0,\
  /* Endpoint In */\
  7, TUSB_DESC_ENDPOINT, _epin, TUSB_XFER_BULK, U16_TO_U8S_LE(_epsize), 0,\
  /* Endpoint Out */\
  7, TUSB_DESC_ENDPOINT, _epout, TUSB_XFER_BULK, U16_TO_U8S_LE(_epsize), 0

enum {
    USB_CFG_DESC_LEN = TUD_CONFIG_DESC_LEN + KEYVAULT_RNDIS_DESC_LEN + TUD_HID_DESC_LEN
};

static const char s_langid[2] = {0x09, 0x04};

/* 字符串描述符 */
const char *usb_str_desc[STRID_COUNT] = {
    s_langid,                      /* 0: 语言 ID */
    "KeyVault",                    /* 1: 制造商 */
    "KeyVault USB Device",         /* 2: 产品 */
    "0001",                        /* 3: 序列号 */
    "KeyVault RNDIS Network",      /* 4: 单一 RNDIS 网络接口 */
    "KeyVault HID Keyboard",       /* 5: 安全免驱键盘输入接口 */
};

const tusb_desc_device_t usb_dev_desc = {
    .bLength            = sizeof(tusb_desc_device_t),
    .bDescriptorType    = TUSB_DESC_DEVICE,
    .bcdUSB             = 0x0200,
    /* 复合设备（含 IAD）：声明为 MISC/Common/IAD */
    .bDeviceClass       = TUSB_CLASS_MISC,
    .bDeviceSubClass    = MISC_SUBCLASS_COMMON,
    .bDeviceProtocol    = MISC_PROTOCOL_IAD,
    .bMaxPacketSize0    = CFG_TUD_ENDPOINT0_SIZE,
    .idVendor           = 0x303A,   /* Espressif VID */
    .idProduct          = 0x4002,   /* 设备 PID */
    .bcdDevice          = 0x0100,
    .iManufacturer      = STRID_MANUFACTURER,
    .iProduct           = STRID_PRODUCT,
    .iSerialNumber      = STRID_SERIAL,
    .bNumConfigurations = 0x01
};

/* 键盘 HID 报表描述符 */
const uint8_t hid_report_desc[] = {
    TUD_HID_REPORT_DESC_KEYBOARD()
};

uint8_t const usb_fs_cfg_desc[USB_CFG_DESC_LEN] = {
    /* 配置号、接口总数(3)、字符串索引、总长度、属性、最大电流(100mA) */
    TUD_CONFIG_DESCRIPTOR(1, ITF_NUM_TOTAL, 0, USB_CFG_DESC_LEN, TUSB_DESC_CONFIG_ATT_REMOTE_WAKEUP, 100),

    /* 接口 0 & 1：RNDIS 网卡（Windows 10/11 原生驱动免驱） */
    KEYVAULT_RNDIS_DESCRIPTOR(ITF_NUM_RNDIS, STRID_RNDIS_INTERFACE,
                              EPNUM_RNDIS_NOTIF, 8,
                              EPNUM_RNDIS_OUT, EPNUM_RNDIS_IN, 64),

    /* 接口 2：HID 键盘（EP3-IN 中断传输，用于物理硬件键入） */
    TUD_HID_DESCRIPTOR(ITF_NUM_HID, STRID_HID_INTERFACE, HID_ITF_PROTOCOL_KEYBOARD,
                       sizeof(hid_report_desc), EPNUM_HID, 8, 10),
};

void usb_desc_set_rndis_mac(const uint8_t mac[6])
{
    (void)mac;
}

/* ── TinyUSB HID 回调实现 ── */
uint8_t const * tud_hid_descriptor_report_cb(uint8_t instance)
{
    (void)instance;
    return hid_report_desc;
}

uint16_t tud_hid_get_report_cb(uint8_t instance, uint8_t report_id, hid_report_type_t report_type, uint8_t* buffer, uint16_t reqlen)
{
    (void)instance;
    (void)report_id;
    (void)report_type;
    (void)buffer;
    (void)reqlen;
    return 0;
}

void tud_hid_set_report_cb(uint8_t instance, uint8_t report_id, hid_report_type_t report_type, uint8_t const* buffer, uint16_t bufsize)
{
    (void)instance;
    (void)report_id;
    (void)report_type;
    (void)buffer;
    (void)bufsize;
}
