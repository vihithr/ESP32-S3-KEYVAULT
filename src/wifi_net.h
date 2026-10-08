/*
 * wifi_net.h —— 应急 Wi-Fi SoftAP 模式
 *
 * 仅在用户开机长按 BOOT 键触发应急模式时启用。
 * 正常运行时不调用本模块任何接口，芯片保持 100% 零射频。
 */
#pragma once

#include "esp_err.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KEYVAULT_WIFI_SSID "KeyVault-Recovery"
#define KEYVAULT_WIFI_PASS "vault2024"
#define KEYVAULT_WIFI_IP   "192.168.4.1"

/**
 * @brief 启动临时 SoftAP（供手机/电脑无线紧急访问 http://192.168.4.1）
 */
esp_err_t wifi_net_start_ap(void);

/**
 * @brief 查询当前 Wi-Fi 是否处于活动状态
 */
bool wifi_net_is_active(void);

#ifdef __cplusplus
}
#endif
