/*
 * usb_desc.h —— USB 原生 RNDIS + HID 复合设备描述符
 *
 * 接口与端点分配：
 *   [0] RNDIS 控制接口   EP1-IN(通知, 8B)
 *   [1] RNDIS 数据接口   EP2-OUT / EP2-IN (64B)
 *   [2] HID 键盘接口     EP3-IN(中断, 8B)
 */
#pragma once

#include <stdint.h>
#include "tusb.h"

/* 描述符实体 */
extern const tusb_desc_device_t usb_dev_desc;
extern uint8_t const usb_fs_cfg_desc[];
extern const char *usb_str_desc[];
extern const uint8_t hid_report_desc[];

#define USB_STR_DESC_COUNT    6

/* 字符串索引 */
#define USB_STRID_LANGID           0
#define USB_STRID_MANUFACTURER     1
#define USB_STRID_PRODUCT          2
#define USB_STRID_SERIAL           3
#define USB_STRID_RNDIS_INTERFACE  4
#define USB_STRID_HID_INTERFACE    5

/* 设置 RNDIS 通道对外宣称的 MAC（Windows 通过 OID 获取） */
void usb_desc_set_rndis_mac(const uint8_t mac[6]);
