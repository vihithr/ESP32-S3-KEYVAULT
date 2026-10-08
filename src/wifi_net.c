/*
 * wifi_net.c —— 应急 Wi-Fi SoftAP 模式实现
 *
 * 仅在用户开机长按 BOOT 键触发应急模式时启用。
 */
#include "wifi_net.h"

#include <string.h>
#include "esp_err.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"

static const char *TAG = "wifi_net";
static bool s_wifi_active = false;

bool wifi_net_is_active(void)
{
    return s_wifi_active;
}

esp_err_t wifi_net_start_ap(void)
{
    if (s_wifi_active) {
        return ESP_OK;
    }

    ESP_LOGW(TAG, "正在启动应急 Wi-Fi SoftAP...");

    esp_netif_t *ap_netif = esp_netif_create_default_wifi_ap();
    if (!ap_netif) {
        ESP_LOGE(TAG, "创建 default_wifi_ap 失败");
        return ESP_FAIL;
    }

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_err_t err = esp_wifi_init(&cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_wifi_init 失败: %d", err);
        return err;
    }

    wifi_config_t wifi_config = {
        .ap = {
            .ssid = KEYVAULT_WIFI_SSID,
            .ssid_len = strlen(KEYVAULT_WIFI_SSID),
            .channel = 1,
            .password = KEYVAULT_WIFI_PASS,
            .max_connection = 4,
            .authmode = WIFI_AUTH_WPA2_PSK,
        },
    };

    if (strlen(KEYVAULT_WIFI_PASS) == 0) {
        wifi_config.ap.authmode = WIFI_AUTH_OPEN;
    }

    err = esp_wifi_set_mode(WIFI_MODE_AP);
    if (err != ESP_OK) return err;
    err = esp_wifi_set_config(WIFI_IF_AP, &wifi_config);
    if (err != ESP_OK) return err;
    err = esp_wifi_start();
    if (err != ESP_OK) return err;

    s_wifi_active = true;
    ESP_LOGW(TAG, "应急 Wi-Fi 已就绪! SSID: %s, 密码: %s, 访问 http://%s",
             KEYVAULT_WIFI_SSID, KEYVAULT_WIFI_PASS, KEYVAULT_WIFI_IP);

    return ESP_OK;
}
