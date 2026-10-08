/*
 * rndis.h —— RNDIS over USB（自定义 TinyUSB 类驱动）
 *
 * 说明：TinyUSB 的网络类驱动是单实例的，且 NCM 与 ECM/RNDIS 互斥
 * （net_device.h 中两者同时启用会 #error）。为了让一个 USB 配置里同时具备
 * NCM 与 RNDIS 两条通道，这里把 RNDIS 实现为一个独立的自定义类驱动，
 * 通过 TinyUSB 的 usbd_app_driver_get_cb() 扩展点注册。
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 设置 RNDIS 通道对外宣称的 MAC（主机通过 OID_GEN_802_3_* 读取） */
void rndis_init(const uint8_t mac[6]);

/* 主机是否已完成 RNDIS 初始化（可以收发数据帧） */
bool rndis_is_ready(void);

/* 发送一帧以太网数据；成功仅表示已提交给 USB，完成由回调通知 */
bool rndis_xmit(const void *frame, uint16_t len);

#ifdef __cplusplus
}
#endif
