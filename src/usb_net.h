/*
 * usb_net.h —— USB 单一网卡 (RNDIS) 设备粘合层
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 设备管理地址（dhcpserver 以此作为网关） */
#define KEYVAULT_IP_ADDR   "192.168.7.1"
#define KEYVAULT_GW_ADDR   "192.168.7.1"
#define KEYVAULT_NETMASK   "255.255.255.0"

#define USB_NET_MAC_LEN    6

typedef enum {
    USB_NET_PORT_RNDIS = 0,       /* RNDIS 单网卡模式 */
    USB_NET_PORT_MAX
} usb_net_port_t;

/**
 * @brief 初始化 USB 单网卡设备栈并创建 netif（含 DHCP Server）
 */
esp_err_t usb_net_init(void);

/**
 * @brief RNDIS 协议层收到以太网帧后上送 lwIP
 */
void usb_net_port_rx(usb_net_port_t port, const uint8_t *frame, uint16_t len, const uint8_t *src_mac);

/**
 * @brief 标记链路已连接/断开
 */
void usb_net_port_set_link(usb_net_port_t port, bool up);

/* 查询当前通道状态（"rndis"/"none"） */
const char *usb_net_active_port_name(void);

/* 查询 USB 设备是否已成功被主机挂载配置 */
bool usb_net_is_mounted(void);

#ifdef __cplusplus
}
#endif
