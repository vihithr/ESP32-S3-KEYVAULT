/*
 * usb_net.c —— USB 单一网卡 (RNDIS) 设备粘合层
 *
 * 专注于单一免驱 RNDIS 网卡：
 *   - 避免多网卡并发导致的主机多设备枚举、IP 争抢与路由冲突
 *   - 简化 MAC 映射与路由，帧收发直接对齐 lwIP 协议栈
 *   - 稳定提供 192.168.7.1 DHCP Server 与管理入口
 */
#include "usb_net.h"

#include <stdlib.h>
#include <string.h>

#include "esp_check.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/esp_netif_net_stack.h"
#include "dhcpserver/dhcpserver_options.h"

#include "tinyusb.h"
#include "tinyusb_default_config.h"

#include "rndis.h"
#include "usb_desc.h"

static const char *TAG = "usb_net";

/* OUI 前缀 0x02 = 本地管理地址（避免与真实物理网卡冲突） */
static const uint8_t s_locally_admin_oui[3] = {0x02, 0x0A, 0x1B};

static const esp_netif_ip_info_t s_ip_info = {
    .ip      = { .addr = ESP_IP4TOADDR(192, 168, 7, 1) },
    .gw      = { .addr = ESP_IP4TOADDR(192, 168, 7, 1) },
    .netmask = { .addr = ESP_IP4TOADDR(255, 255, 255, 0) },
};

static esp_netif_t *s_netif = NULL;
static uint8_t s_netif_mac[USB_NET_MAC_LEN];
static bool s_port_link = false;

/* ────────────────────────── MAC 辅助 ────────────────────────── */

static void derive_mac_addresses(void)
{
    uint8_t base[USB_NET_MAC_LEN] = {0};
    esp_err_t ret = esp_read_mac(base, ESP_MAC_ETH);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "esp_read_mac(ETH) 失败(%s)，使用默认后缀", esp_err_to_name(ret));
        memset(base + 3, 0x33, 3);
    }

    memcpy(s_netif_mac, s_locally_admin_oui, sizeof(s_locally_admin_oui));
    memcpy(s_netif_mac + 3, base + 3, 3); /* 保留芯片唯一后缀 */
}

/* ────────────────────────── 收发接口 ────────────────────────── */

void usb_net_port_rx(usb_net_port_t port, const uint8_t *frame, uint16_t len, const uint8_t *src_mac)
{
    (void)port;
    (void)src_mac;

    if (s_netif == NULL || len < 14) {
        return;
    }

    uint8_t *copy = malloc(len);
    if (copy == NULL) {
        return;
    }
    memcpy(copy, frame, len);

    if (esp_netif_receive(s_netif, copy, len, NULL) != ESP_OK) {
        free(copy);
    }
}

void usb_net_port_set_link(usb_net_port_t port, bool up)
{
    (void)port;
    if (s_port_link != up) {
        ESP_LOGI(TAG, "RNDIS 网络链路: %s", up ? "UP" : "DOWN");
    }
    s_port_link = up;
}

bool usb_net_is_mounted(void)
{
    return tud_mounted();
}

const char *usb_net_active_port_name(void)
{
    if (!tud_mounted()) {
        return "none";
    }
    if (s_port_link && rndis_is_ready()) {
        return "rndis";
    }
    return "none";
}

/* ────────────────────────── netif glue ────────────────────────── */

static void netif_free_rx(void *h, void *buffer)
{
    (void)h;
    free(buffer);
}

static esp_err_t netif_transmit(void *h, void *buffer, size_t len)
{
    (void)h;
    if (len < 14 || len > 1514) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!rndis_is_ready()) {
        return ESP_ERR_INVALID_STATE;
    }
    return rndis_xmit(buffer, (uint16_t)len) ? ESP_OK : ESP_FAIL;
}

static esp_err_t create_usb_netif(void)
{
    esp_netif_inherent_config_t base_cfg = {
        .flags      = ESP_NETIF_DHCP_SERVER | ESP_NETIF_FLAG_AUTOUP,
        .ip_info    = &s_ip_info,
        .if_key     = "usb_net",
        .if_desc    = "KeyVault RNDIS Network",
        .route_prio = 10,
    };
    memcpy(base_cfg.mac, s_netif_mac, USB_NET_MAC_LEN);

    esp_netif_driver_ifconfig_t driver_cfg = {
        .handle                = (void *)1,   /* 静态单例，非空即可 */
        .transmit              = netif_transmit,
        .driver_free_rx_buffer = netif_free_rx,
    };

    static const esp_netif_netstack_config_t netstack_cfg = {
        .lwip = {
            .init_fn  = ethernetif_init,
            .input_fn = ethernetif_input,
        },
    };

    const esp_netif_config_t cfg = {
        .base   = &base_cfg,
        .driver = &driver_cfg,
        .stack  = &netstack_cfg,
    };

    s_netif = esp_netif_new(&cfg);
    ESP_RETURN_ON_FALSE(s_netif != NULL, ESP_FAIL, TAG, "esp_netif_new 失败");

    uint32_t lease_time = 1;   /* 短租约，适配热拔插快速重连 */
    ESP_RETURN_ON_ERROR(esp_netif_dhcps_option(s_netif, ESP_NETIF_OP_SET, IP_ADDRESS_LEASE_TIME,
                                               &lease_time, sizeof(lease_time)),
                        TAG, "DHCP Server 选项设置失败");

    esp_netif_action_start(s_netif, 0, 0, 0);
    return ESP_OK;
}

/* ────────────────────────── 初始化 ────────────────────────── */

esp_err_t usb_net_init(void)
{
    derive_mac_addresses();

    usb_desc_set_rndis_mac(s_netif_mac);
    rndis_init(s_netif_mac);

    const tinyusb_config_t tusb_cfg = {
        .port = TINYUSB_PORT_FULL_SPEED_0,
        .phy = {
            .skip_setup      = false,
            .self_powered    = false,
            .vbus_monitor_io = -1,
        },
        .task = TINYUSB_TASK_CUSTOM(8192, 5, 1),
        .descriptor = {
            .device            = &usb_dev_desc,
            .string            = usb_str_desc,
            .string_count      = USB_STR_DESC_COUNT,
            .full_speed_config = usb_fs_cfg_desc,
        },
    };
    ESP_RETURN_ON_ERROR(tinyusb_driver_install(&tusb_cfg), TAG, "TinyUSB 驱动安装失败");

    ESP_RETURN_ON_ERROR(create_usb_netif(), TAG, "USB netif 创建失败");

    ESP_LOGI(TAG, "KeyVault USB 单一 RNDIS 网卡就绪，访问地址 http://%s", KEYVAULT_IP_ADDR);
    ESP_LOGI(TAG, "RNDIS MAC: %02X:%02X:%02X:%02X:%02X:%02X",
             s_netif_mac[0], s_netif_mac[1], s_netif_mac[2],
             s_netif_mac[3], s_netif_mac[4], s_netif_mac[5]);
    return ESP_OK;
}
