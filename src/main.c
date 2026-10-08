/*
 * KeyVault USB —— ESP32-S3 离线密钥管理设备
 *
 * 功能：
 *   - USB 复合设备（CDC-NCM + RNDIS），插入即自动组网（内置 DHCP Server）
 *   - 不使用 Wi-Fi / 蓝牙，固件层面已关闭射频相关功能
 *   - AES-256-GCM 加密存储账号密码
 *   - 主密码认证 + 会话令牌 + 自动锁定
 *   - 随机密码生成
 *
 * 使用方法：
 *   1. 用 USB 线连接 PC 或手机（USB-OTG：GPIO19(D-) / GPIO20(D+)）
 *   2. 主机自动获取 IP，浏览器访问 http://192.168.7.1
 *   3. 首次使用设置主密码
 *   4. 之后每次需要主密码解锁
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_err.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "mbedtls/base64.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/gpio.h"
#include "nvs_flash.h"
#include "hal/usb_serial_jtag_ll.h"
#include "hal/usb_wrap_ll.h"

#include "keyvault.h"
#include "usb_net.h"
#include "usb_hid.h"
#include "wifi_net.h"
#include "web_content.h"
#include "json_util.h"
#include "e2ee.h"

#define TAG "KeyVault"

#define LED_GPIO          GPIO_NUM_2
#define BOOT_BUTTON_GPIO  GPIO_NUM_0

/* 备份最大体积：仓库满载约 63KB，base64 后约 84KB，再加 JSON 开销。
 * 这个尺寸的 body 绝不能放栈上（HTTP 任务只有 8KB 栈）。 */
#define IMPORT_MAX_BODY  (96 * 1024)

static httpd_handle_t s_server = NULL;

/* ── 硬件物理按键 2FA 确认机制 ── */
static SemaphoreHandle_t s_auth_sem = NULL;
static volatile bool s_waiting_auth = false;
static volatile int64_t s_last_boot_press_us = 0;

/* ── 嵌入的网页（由 web_content.c 提供） ── */

/* ── 后台看护任务：LED 指示 + USB 拔插自锁 + 物理按键确认 + 长按 BOOT 键 10 秒开启应急 Wi-Fi ── */
static void monitor_task(void *arg)
{
    int boot_held_ticks = 0;
    bool led_on = false;
    uint32_t loop_count = 0;

    while (true) {
        vTaskDelay(pdMS_TO_TICKS(20));  /* 20ms 高频极速采样，杜绝漏按 */
        loop_count++;

        /* 1. 检测 BOOT 按键 (低电平有效) */
        if (gpio_get_level(BOOT_BUTTON_GPIO) == 0) {
            s_last_boot_press_us = esp_timer_get_time();
            boot_held_ticks++;

            /* A. 若当前有 Web 登录/设置/查看请求正等待物理按键授权，短按瞬间放行 */
            if (s_waiting_auth && s_auth_sem != NULL) {
                s_waiting_auth = false;
                xSemaphoreGive(s_auth_sem);
                ESP_LOGI(TAG, ">>> monitor_task: 检测到硬件 BOOT 键按下，物理授权通过！<<<");
            }
            /* B. 若系统处于 HID 键盘单次安全输入武装状态，短按瞬间触发物理键入 (仅触发一次) */
            else if (usb_hid_is_armed() && boot_held_ticks == 1) {
                ESP_LOGI(TAG, ">>> monitor_task: 检测到 BOOT 键按下，触发安全硬件模拟键入！<<<");
                gpio_set_level(LED_GPIO, 1);
                usb_hid_trigger();
                gpio_set_level(LED_GPIO, 0);
            }

            /* 按下 3~10 秒内：LED 快速爆闪，视觉提示用户正在长按计时 (20ms * 150 = 3000ms) */
            if (boot_held_ticks >= 150 && boot_held_ticks < 500) {
                led_on = !led_on;
                gpio_set_level(LED_GPIO, led_on ? 1 : 0);
            }
            /* 持续按下达到 10 秒 (20ms * 500 = 10000ms)：激活应急 Wi-Fi */
            else if (boot_held_ticks == 500) {
                ESP_LOGW(TAG, "=================================================");
                ESP_LOGW(TAG, ">>> BOOT 键长按 10 秒达成：立即激活【应急 Wi-Fi 模式】！<<<");
                ESP_LOGW(TAG, "=================================================");
                wifi_net_start_ap();
                gpio_set_level(LED_GPIO, 1);
                vTaskDelay(pdMS_TO_TICKS(3000));
            } else if (boot_held_ticks > 500) {
                gpio_set_level(LED_GPIO, 1);
            }
            continue;
        } else {
            boot_held_ticks = 0;
        }

        /* 2. 若正在等待用户按键授权确认：由 wait_for_physical_button 接管 LED 闪烁 */
        if (s_waiting_auth) {
            continue;
        }

        /* 3. 若处于 HID 安全输入武装待命状态：LED 快速双闪警示 (100ms 翻转一次) */
        if (usb_hid_is_armed()) {
            if (loop_count % 5 == 0) {
                led_on = !led_on;
                gpio_set_level(LED_GPIO, led_on ? 1 : 0);
            }
            continue;
        }


        /* 4. 正常运行 LED 指示灯节奏 */
        if (wifi_net_is_active()) {
            /* Wi-Fi 模式：1 秒闪烁 1 次 (500ms 亮 / 500ms 灭，50 * 20ms = 1000ms) */
            if (loop_count % 25 == 0) {
                led_on = !led_on;
                gpio_set_level(LED_GPIO, led_on ? 1 : 0);
            }
        } else {
            /* USB 模式：根据解锁状态与挂载状态呼吸闪烁 */
            int cycle = (vault_is_unlocked() ? 50 : (usb_net_is_mounted() ? 25 : 10));
            if (loop_count % cycle == 0) {
                led_on = !led_on;
                gpio_set_level(LED_GPIO, led_on ? 1 : 0);
            }
        }
    }
}

/* 等待物理按键授权确认（双保险：事件锁存 + 信号量 + 50ms 电平轮询 + LED 强反馈） */
static bool wait_for_physical_button(int64_t req_start_us, uint32_t timeout_ms)
{
    /* 1. 宽限窗口检查：若用户在发起请求前后（req_start_us - 1.5s 至今）已经按过了 BOOT 键 */
    if (s_last_boot_press_us >= (req_start_us - 1500000LL)) {
        ESP_LOGI(TAG, "用户在请求窗口期内已轻按 BOOT 键，直接放行授权！");
        gpio_set_level(LED_GPIO, 1);
        vTaskDelay(pdMS_TO_TICKS(300));
        return true;
    }

    /* 2. 准备等待全新按键事件 */
    if (s_auth_sem != NULL) {
        xSemaphoreTake(s_auth_sem, 0);   /* 清除残留信号 */
    }
    s_waiting_auth = true;
    ESP_LOGI(TAG, "等待板载 [BOOT] 键物理确认 (超时 %u 秒)...", (unsigned)(timeout_ms / 1000));

    uint32_t elapsed_ms = 0;
    bool confirmed = false;

    while (elapsed_ms < timeout_ms) {
        /* A. 尝试获取信号量 (50ms) */
        if (s_auth_sem != NULL && xSemaphoreTake(s_auth_sem, pdMS_TO_TICKS(50)) == pdTRUE) {
            confirmed = true;
            break;
        }

        /* B. 双保险：直接读取 GPIO 0 电平 */
        if (gpio_get_level(BOOT_BUTTON_GPIO) == 0) {
            s_last_boot_press_us = esp_timer_get_time();
            confirmed = true;
            ESP_LOGI(TAG, "直接读取到 BOOT 键低电平，放行授权！");
            break;
        }

        elapsed_ms += 50;

        /* C. 等待期间 LED 快速交替闪烁，给予强烈的视觉提示 (每 100ms 翻转) */
        gpio_set_level(LED_GPIO, ((elapsed_ms / 100) % 2) ? 1 : 0);
    }

    s_waiting_auth = false;

    if (confirmed) {
        /* 授权成功：LED 常亮 300ms 给出明确的物理反馈 */
        gpio_set_level(LED_GPIO, 1);
        vTaskDelay(pdMS_TO_TICKS(300));
        ESP_LOGI(TAG, "物理授权完成！");
        return true;
    }

    ESP_LOGW(TAG, "物理按键确认超时 (%u ms)", (unsigned)timeout_ms);
    return false;
}

/* ── JSON 辅助 ──
 * 解析与转义统一走 json_util：读取侧要能正确处理 \" 等转义序列，
 * 否则用户密码里出现引号时会静默丢字符。 */

/* 分块发送一个 JSON 片段，避免为长列表做整体堆分配 */
static esp_err_t json_chunk(httpd_req_t *req, const char *s)
{
    return httpd_resp_send_chunk(req, s, HTTPD_RESP_USE_STRLEN);
}

/* 分块发送一个转义后的字符串字段 */
static esp_err_t json_chunk_escaped(httpd_req_t *req, const char *raw, char *buf, size_t buf_len)
{
    json_escape_str(buf, buf_len, raw);
    return json_chunk(req, buf);
}

/* 从请求头获取 token */
static bool get_token(httpd_req_t *req, char *token_out, size_t len)
{
    size_t hdr_len = httpd_req_get_hdr_value_len(req, "X-Token");
    if (hdr_len == 0 || hdr_len >= len) return false;
    httpd_req_get_hdr_value_str(req, "X-Token", token_out, len);
    return true;
}

/* 从请求头获取 E2EE 会话 ID */
static bool get_e2ee_session(httpd_req_t *req, char *session_out, size_t max_len)
{
    size_t hdr_len = httpd_req_get_hdr_value_len(req, "X-E2EE-Session");
    if (hdr_len == 0 || hdr_len >= max_len) return false;
    if (httpd_req_get_hdr_value_str(req, "X-E2EE-Session", session_out, max_len) != ESP_OK) {
        return false;
    }
    return e2ee_is_session_valid(session_out);
}

/* 统一发送 JSON 响应（若客户端启用了 E2EE，自动加密返回） */
static esp_err_t send_json_resp(httpd_req_t *req, const char *json_str)
{
    char session_id[E2EE_SESSION_ID_LEN];
    if (get_e2ee_session(req, session_id, sizeof(session_id))) {
        size_t json_len = strlen(json_str);
        size_t max_resp = json_len * 2 + 160;
        char *enc_resp = malloc(max_resp);
        if (enc_resp) {
            esp_err_t err = e2ee_encrypt_json_resp(session_id, (const uint8_t *)json_str, json_len,
                                                   enc_resp, max_resp);
            if (err == ESP_OK) {
                httpd_resp_set_type(req, "application/json");
                esp_err_t ret = httpd_resp_sendstr(req, enc_resp);
                free(enc_resp);
                return ret;
            }
            free(enc_resp);
        }
    }
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, json_str);
}

/* 统一鉴权入口：校验会话令牌并即时擦除栈上的副本 */
static bool authorized(httpd_req_t *req)
{
    char token[VAULT_SESSION_TOKEN_LEN];
    if (!get_token(req, token, sizeof(token))) {
        ESP_LOGW(TAG, "鉴权失败: 未提供 X-Token 头 (URI: %s)", req->uri);
        return false;
    }
    bool ok = vault_validate_token(token);
    if (!ok) {
        ESP_LOGW(TAG, "鉴权失败: Token 无效或密库已超时锁定 (URI: %s)", req->uri);
    }
    vault_secure_zero(token, sizeof(token));
    return ok;
}

/* 未授权统一应答 */
static esp_err_t deny(httpd_req_t *req)
{
    return send_json_resp(req, "{\"ok\":false,\"error\":\"unauthorized\"}");
}

/* 读取原始 POST body。 */
static int read_raw_body(httpd_req_t *req, char *buf, size_t max_len)
{
    if (max_len == 0) {
        return 0;
    }
    size_t want = (size_t)req->content_len;
    size_t total = 0;
    char sink[64];

    while (total < want) {
        size_t remain = want - total;
        if (total < max_len - 1) {
            size_t room = max_len - 1 - total;
            int n = httpd_req_recv(req, buf + total, (room < remain) ? room : remain);
            if (n < 0) { buf[total] = '\0'; return 0; }
            if (n == 0) break;
            total += (size_t)n;
        } else {
            size_t chunk = (sizeof(sink) < remain) ? sizeof(sink) : remain;
            int n = httpd_req_recv(req, sink, chunk);
            if (n < 0) { buf[max_len - 1] = '\0'; return (int)(max_len - 1); }
            if (n == 0) break;
            total += (size_t)n;
        }
    }
    buf[(total < max_len) ? total : (max_len - 1)] = '\0';
    return (int)total;
}

/* 读取 POST body（若为 E2EE 加密请求，自动解密还原明文） */
static int read_body(httpd_req_t *req, char *buf, size_t max_len)
{
    char session_id[E2EE_SESSION_ID_LEN];
    bool is_e2ee = get_e2ee_session(req, session_id, sizeof(session_id));

    if (!is_e2ee) {
        return read_raw_body(req, buf, max_len);
    }

    /* E2EE 加密请求处理 */
    size_t raw_cap = (req->content_len + 1 > 512) ? (req->content_len + 1) : 512;
    char *raw = malloc(raw_cap);
    if (!raw) return 0;

    int n = read_raw_body(req, raw, raw_cap);
    if (n <= 0) {
        free(raw);
        return 0;
    }

    char iv[32] = {0};
    char tag[40] = {0};
    if (!json_get_str_field(raw, "iv", iv, sizeof(iv)) ||
        !json_get_str_field(raw, "tag", tag, sizeof(tag))) {
        /* 非标准密文格式，回退为原始明文处理 */
        size_t cpy = (size_t)n < max_len - 1 ? (size_t)n : max_len - 1;
        memcpy(buf, raw, cpy);
        buf[cpy] = '\0';
        free(raw);
        return (int)cpy;
    }

    size_t cipher_len = raw_cap;
    char *cipher = malloc(cipher_len);
    if (!cipher) {
        free(raw);
        return 0;
    }
    if (!json_get_str_field(raw, "data", cipher, cipher_len)) {
        free(cipher);
        free(raw);
        return 0;
    }
    free(raw);

    size_t plain_len = 0;
    esp_err_t err = e2ee_decrypt(session_id, iv, tag, cipher,
                                 (uint8_t *)buf, max_len - 1, &plain_len);
    free(cipher);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "E2EE 解密请求失败: %d", err);
        return 0;
    }
    buf[plain_len] = '\0';
    return (int)plain_len;
}


/* ── HTTP 处理函数 ── */

/* GET / → 主页面 */
static esp_err_t handler_root(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_send(req, WEB_INDEX_HTML, WEB_INDEX_HTML_LEN);
    return ESP_OK;
}

/* POST /api/e2ee/handshake {client_pub:"..."} */
static esp_err_t handler_e2ee_handshake(httpd_req_t *req)
{
    char body[256];
    if (read_raw_body(req, body, sizeof(body)) == 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "empty body");
        return ESP_FAIL;
    }
    char client_pub[128];
    if (!json_get_str_field(body, "client_pub", client_pub, sizeof(client_pub))) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing client_pub");
        return ESP_FAIL;
    }
    char server_pub[128];
    char session_id[E2EE_SESSION_ID_LEN];
    esp_err_t err = e2ee_handshake(client_pub, server_pub, session_id, sizeof(session_id));
    if (err != ESP_OK) {
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"handshake failed\"}");
        return ESP_OK;
    }
    char resp[256];
    snprintf(resp, sizeof(resp),
             "{\"ok\":true,\"server_pub\":\"%s\",\"session_id\":\"%s\"}",
             server_pub, session_id);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, resp);
    return ESP_OK;
}

/* GET /api/health — 闪存健康度与自愈监控 */
static esp_err_t handler_health(httpd_req_t *req)
{
    /* 若携带有有效 Token，顺延会话心跳活跃时间 */
    char token[VAULT_SESSION_TOKEN_LEN];
    if (get_token(req, token, sizeof(token))) {
        vault_validate_token(token);
        vault_secure_zero(token, sizeof(token));
    }

    vault_health_stats_t stats;
    esp_err_t err = vault_get_health_stats(&stats);
    if (err != ESP_OK) {
        return send_json_resp(req, "{\"ok\":false}");
    }
    char resp[384];
    snprintf(resp, sizeof(resp),
             "{\"ok\":true,\"writes\":%u,\"heals\":%u,\"creds\":%u,\"kvs\":%u,"
             "\"max_creds\":%u,\"max_kvs\":%u,\"free_entries\":%u,\"used_entries\":%u,"
             "\"read_only\":%s}",
             (unsigned)stats.total_writes,
             (unsigned)stats.heal_count,
             (unsigned)stats.cred_count,
             (unsigned)stats.kv_count,
             (unsigned)stats.max_creds,
             (unsigned)stats.max_kvs,
             (unsigned)stats.free_entries,
             (unsigned)stats.used_entries,
             stats.read_only_safe_mode ? "true" : "false");
    return send_json_resp(req, resp);
}

/* GET /api/status —— 只暴露"是否已初始化"与链路状态。
 * 原来还会返回 unlocked，等于让未认证者能探测设备当前是否处于解锁态，
 * 而这个信息对页面初始化并无用处（UI 只用 setup）。 */
static esp_err_t handler_status(httpd_req_t *req)
{
    char resp[256];
    const char *ip_str = wifi_net_is_active() ? KEYVAULT_WIFI_IP : KEYVAULT_IP_ADDR;
    const char *link_str = wifi_net_is_active() ? "wifi" : usb_net_active_port_name();
    snprintf(resp, sizeof(resp),
             "{\"setup\":%s,\"usb_mounted\":%s,\"link\":\"%s\",\"ip\":\"%s\"}",
             vault_is_setup() ? "true" : "false",
             (wifi_net_is_active() || usb_net_is_mounted()) ? "true" : "false",
             link_str,
             ip_str);
    return send_json_resp(req, resp);
}

/* GET /api/usb — USB / 网络连接状态（用于界面显示当前协议） */
static esp_err_t handler_usb(httpd_req_t *req)
{
    /* 若携带有有效 Token，顺延会话心跳活跃时间 */
    char token[VAULT_SESSION_TOKEN_LEN];
    if (get_token(req, token, sizeof(token))) {
        vault_validate_token(token);
        vault_secure_zero(token, sizeof(token));
    }

    char resp[160];
    const char *port_name = wifi_net_is_active() ? "wifi" : usb_net_active_port_name();
    const char *ip_str = wifi_net_is_active() ? KEYVAULT_WIFI_IP : KEYVAULT_IP_ADDR;
    snprintf(resp, sizeof(resp),
             "{\"mounted\":%s,\"active_port\":\"%s\",\"ip\":\"%s\"}",
             (wifi_net_is_active() || usb_net_is_mounted()) ? "true" : "false",
             port_name,
             ip_str);
    return send_json_resp(req, resp);
}

/* POST /api/reboot — 重启设备（需已解锁：
 * 未鉴权时任何能访问 192.168.7.1 的进程都能把设备踢下线） */
static esp_err_t handler_reboot(httpd_req_t *req)
{
    if (!authorized(req)) {
        return deny(req);
    }
    send_json_resp(req, "{\"ok\":true}");
    vTaskDelay(pdMS_TO_TICKS(500));
    esp_restart();
    return ESP_OK;
}

/* POST /api/setup {password:"..."} */
static esp_err_t handler_setup(httpd_req_t *req)
{
    int64_t req_start_us = esp_timer_get_time();

    char body[512];
    if (read_body(req, body, sizeof(body)) == 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "empty body");
        return ESP_FAIL;
    }

    char password[256];
    if (!json_get_str_field(body, "password", password, sizeof(password))) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing password");
        return ESP_FAIL;
    }

    /* vault_setup 成功后即处于解锁态并直接回传令牌 */
    char token[VAULT_SESSION_TOKEN_LEN];
    esp_err_t err = vault_setup(password, token, sizeof(token));
    vault_secure_zero(password, sizeof(password));
    vault_secure_zero(body, sizeof(body));

    if (err != ESP_OK) {
        char resp[128];
        snprintf(resp, sizeof(resp), "{\"ok\":false,\"error\":\"设置失败 (%d)\"}", err);
        return send_json_resp(req, resp);
    }

    /* 首次设置增加硬件物理按键确认，确保本地物理人员操作 */
    if (!wait_for_physical_button(req_start_us, 15000)) {
        vault_lock();
        return send_json_resp(req, "{\"ok\":false,\"error\":\"硬件确认超时：请在 15 秒内轻按开发板上的 [BOOT] 键以授权\"}");
    }

    char resp[128];
    snprintf(resp, sizeof(resp), "{\"ok\":true,\"token\":\"%s\"}", token);
    return send_json_resp(req, resp);
}

/* POST /api/login {password:"..."} */
static esp_err_t handler_login(httpd_req_t *req)
{
    int64_t req_start_us = esp_timer_get_time();

    char body[512];
    if (read_body(req, body, sizeof(body)) == 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "empty body");
        return ESP_FAIL;
    }

    char password[256];
    if (!json_get_str_field(body, "password", password, sizeof(password))) {
        vault_secure_zero(body, sizeof(body));
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "missing password");
        return ESP_FAIL;
    }

    char token[VAULT_SESSION_TOKEN_LEN];
    esp_err_t err = vault_unlock(password, token, sizeof(token));
    vault_secure_zero(password, sizeof(password));
    vault_secure_zero(body, sizeof(body));

    if (err != ESP_OK) {
        return send_json_resp(req, "{\"ok\":false,\"error\":\"密码错误\"}");
    }

    /* ── 硬件安全 2FA：物理按键授权确认 ──
     * 密码验证成功后，不直接返回 Token，必须等待操作者在物理设备上轻按 [BOOT] 键 */
    if (!wait_for_physical_button(req_start_us, 15000)) {
        vault_lock(); /* 撤销解锁状态 */
        return send_json_resp(req, "{\"ok\":false,\"error\":\"硬件确认超时：请在 15 秒内轻按开发板上的 [BOOT] 键以授权\"}");
    }

    char resp[128];
    snprintf(resp, sizeof(resp), "{\"ok\":true,\"token\":\"%s\"}", token);
    return send_json_resp(req, resp);
}

/* GET /api/creds — 列出所有凭证（仅名称和URL） */
static esp_err_t handler_list_creds(httpd_req_t *req)
{
    if (!authorized(req)) {
        return deny(req);
    }

    int cnt = vault_cred_count();
    char session_id[E2EE_SESSION_ID_LEN];
    bool is_e2ee = get_e2ee_session(req, session_id, sizeof(session_id));

    if (!is_e2ee) {
        /* 流式输出：不按条数估算缓冲区，避免长字段导致的越界 */
        char esc[VAULT_MAX_USER_LEN * 2 + 1];

        httpd_resp_set_type(req, "application/json");
        json_chunk(req, "{\"ok\":true,\"creds\":[");
        bool first = true;
        for (int i = 0; i < cnt; i++) {
            vault_cred_t cred;
            if (vault_get_cred(i, &cred) != ESP_OK) continue;
            if (!first) json_chunk(req, ",");
            first = false;
            json_chunk(req, "{\"name\":\"");
            json_chunk_escaped(req, cred.name, esc, sizeof(esc));
            json_chunk(req, "\",\"url\":\"");
            json_chunk_escaped(req, cred.url, esc, sizeof(esc));
            json_chunk(req, "\",\"user\":\"");
            json_chunk_escaped(req, cred.username, esc, sizeof(esc));
            json_chunk(req, "\"}");
            vault_secure_zero(&cred, sizeof(cred));
        }
        char tail[32];
        snprintf(tail, sizeof(tail), "],\"count\":%d}", cnt);
        json_chunk(req, tail);
        return httpd_resp_send_chunk(req, NULL, 0);
    }

    /* E2EE 加密输出 */
    size_t est_size = (size_t)cnt * 200 + 64;
    if (est_size < 512) est_size = 512;
    char *buf = malloc(est_size);
    if (!buf) {
        return send_json_resp(req, "{\"ok\":false,\"error\":\"no_mem\"}");
    }
    size_t offset = snprintf(buf, est_size, "{\"ok\":true,\"creds\":[");
    bool first = true;
    for (int i = 0; i < cnt; i++) {
        vault_cred_t cred;
        if (vault_get_cred(i, &cred) != ESP_OK) continue;
        if (!first && offset < est_size) buf[offset++] = ',';
        first = false;
        char item[512];
        char esc_n[VAULT_MAX_NAME_LEN * 2 + 1];
        char esc_u[VAULT_MAX_URL_LEN * 2 + 1];
        char esc_usr[VAULT_MAX_USER_LEN * 2 + 1];
        json_escape_str(esc_n, sizeof(esc_n), cred.name);
        json_escape_str(esc_u, sizeof(esc_u), cred.url);
        json_escape_str(esc_usr, sizeof(esc_usr), cred.username);
        int item_len = snprintf(item, sizeof(item),
                                "{\"name\":\"%s\",\"url\":\"%s\",\"user\":\"%s\"}",
                                esc_n, esc_u, esc_usr);
        vault_secure_zero(&cred, sizeof(cred));
        if (offset + item_len < est_size) {
            memcpy(buf + offset, item, item_len);
            offset += item_len;
        }
    }
    int tail_len = snprintf(buf + offset, est_size - offset, "],\"count\":%d}", cnt);
    offset += tail_len;
    buf[offset] = '\0';

    esp_err_t ret = send_json_resp(req, buf);
    free(buf);
    return ret;
}

/* GET /api/cred/<idx> — 获取单条凭证（含密码） */
static esp_err_t handler_get_cred(httpd_req_t *req)
{
    int64_t req_start_us = esp_timer_get_time();

    if (!authorized(req)) {
        return deny(req);
    }

    /* ── 硬件安全 2FA：物理按键授权确认 ──
     * 查看/复制密码明文必须经由操作者在物理设备上轻按 [BOOT] 键确认，
     * 杜绝后台木马脚本静默爬取凭证库。 */
    if (!wait_for_physical_button(req_start_us, 15000)) {
        return send_json_resp(req, "{\"ok\":false,\"error\":\"硬件确认超时：请在 15 秒内轻按开发板上的 [BOOT] 键以授权查看\"}");
    }

    /* 从 URI 提取 index: /api/cred/0, /api/cred/1, ... */
    const char *uri = req->uri;
    const char *prefix = "/api/cred/";
    if (strncmp(uri, prefix, strlen(prefix)) != 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad uri");
        return ESP_FAIL;
    }
    int idx = atoi(uri + strlen(prefix));

    vault_cred_t cred;
    esp_err_t err = vault_get_cred(idx, &cred);
    if (err != ESP_OK) {
        return send_json_resp(req, "{\"ok\":false,\"error\":\"not found\"}");
    }

    /* 逐字段转义输出（名称/URL/用户名/密码都可能含引号或反斜杠） */
    char esc_name[VAULT_MAX_NAME_LEN * 2 + 1];
    char esc_url[VAULT_MAX_URL_LEN * 2 + 1];
    char esc_user[VAULT_MAX_USER_LEN * 2 + 1];
    char esc_pass[VAULT_MAX_PASS_LEN * 2 + 1];
    json_escape_str(esc_name, sizeof(esc_name), cred.name);
    json_escape_str(esc_url, sizeof(esc_url), cred.url);
    json_escape_str(esc_user, sizeof(esc_user), cred.username);
    json_escape_str(esc_pass, sizeof(esc_pass), cred.password);
    vault_secure_zero(&cred, sizeof(cred));

    char resp[sizeof(esc_name) + sizeof(esc_url) + sizeof(esc_user) + sizeof(esc_pass) + 64];
    snprintf(resp, sizeof(resp),
             "{\"ok\":true,\"cred\":{\"name\":\"%s\",\"url\":\"%s\",\"user\":\"%s\",\"pass\":\"%s\"}}",
             esc_name, esc_url, esc_user, esc_pass);
    vault_secure_zero(esc_pass, sizeof(esc_pass));

    esp_err_t send_err = send_json_resp(req, resp);
    vault_secure_zero(resp, sizeof(resp));
    return send_err;
}

/* POST /api/creds {name,url,user,pass} — 添加凭证 */
static esp_err_t handler_add_cred(httpd_req_t *req)
{
    if (!authorized(req)) {
        return deny(req);
    }

    char body[1024];
    if (read_body(req, body, sizeof(body)) == 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "empty body");
        return ESP_FAIL;
    }

    vault_cred_t cred;
    memset(&cred, 0, sizeof(cred));
    json_get_str_field(body, "name", cred.name, VAULT_MAX_NAME_LEN);
    json_get_str_field(body, "url",  cred.url,  VAULT_MAX_URL_LEN);
    json_get_str_field(body, "user", cred.username, VAULT_MAX_USER_LEN);
    json_get_str_field(body, "pass", cred.password, VAULT_MAX_PASS_LEN);

    if (strlen(cred.name) == 0) {
        return send_json_resp(req, "{\"ok\":false,\"error\":\"name required\"}");
    }

    esp_err_t err = vault_add_cred(&cred);
    vault_secure_zero(&cred, sizeof(cred));
    vault_secure_zero(body, sizeof(body));

    if (err != ESP_OK) {
        /* 典型原因：条目数达上限，只读模式，或 NVS 分区写满 */
        return send_json_resp(req, err == ESP_ERR_NO_MEM
                           ? "{\"ok\":false,\"error\":\"存储已满或已达条数上限\"}"
                           : (err == ESP_ERR_NOT_ALLOWED
                              ? "{\"ok\":false,\"error\":\"设备处于安全只读保护模式\"}"
                              : "{\"ok\":false,\"error\":\"写入失败\"}"));
    }

    return send_json_resp(req, "{\"ok\":true}");
}

/* POST /api/cred/update {id,cred:{...}} — 更新凭证 */
static esp_err_t handler_update_cred(httpd_req_t *req)
{
    if (!authorized(req)) {
        return deny(req);
    }

    char body[1024];
    if (read_body(req, body, sizeof(body)) == 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "empty body");
        return ESP_FAIL;
    }

    int idx = -1;
    json_get_int_field(body, "id", &idx);
    if (idx < 0) {
        return send_json_resp(req, "{\"ok\":false,\"error\":\"missing id\"}");
    }

    /* 解析嵌套的 cred 对象 */
    const char *cred_start = strstr(body, "\"cred\":");
    if (!cred_start) {
        return send_json_resp(req, "{\"ok\":false,\"error\":\"missing cred\"}");
    }

    vault_cred_t cred;
    memset(&cred, 0, sizeof(cred));
    json_get_str_field(cred_start, "name", cred.name, VAULT_MAX_NAME_LEN);
    json_get_str_field(cred_start, "url",  cred.url,  VAULT_MAX_URL_LEN);
    json_get_str_field(cred_start, "user", cred.username, VAULT_MAX_USER_LEN);
    json_get_str_field(cred_start, "pass", cred.password, VAULT_MAX_PASS_LEN);

    esp_err_t err = vault_update_cred(idx, &cred);
    vault_secure_zero(&cred, sizeof(cred));
    vault_secure_zero(body, sizeof(body));

    if (err != ESP_OK) {
        return send_json_resp(req, err == ESP_ERR_NOT_FOUND
                           ? "{\"ok\":false,\"error\":\"条目不存在\"}"
                           : (err == ESP_ERR_NOT_ALLOWED
                              ? "{\"ok\":false,\"error\":\"设备处于安全只读保护模式\"}"
                              : "{\"ok\":false,\"error\":\"写入失败\"}"));
    }

    return send_json_resp(req, "{\"ok\":true}");
}

/* POST /api/cred/delete {id} — 删除凭证 */
static esp_err_t handler_delete_cred(httpd_req_t *req)
{
    if (!authorized(req)) {
        return deny(req);
    }

    char body[256];
    if (read_body(req, body, sizeof(body)) == 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "empty body");
        return ESP_FAIL;
    }

    int idx = -1;
    json_get_int_field(body, "id", &idx);
    if (idx < 0) {
        return send_json_resp(req, "{\"ok\":false,\"error\":\"missing id\"}");
    }

    esp_err_t err = vault_delete_cred(idx);
    char resp[64];
    snprintf(resp, sizeof(resp), "{\"ok\":%s}", err == ESP_OK ? "true" : "false");
    return send_json_resp(req, resp);
}

/* POST /api/generate {length,upper,lower,digits,symbols} */
static esp_err_t handler_generate(httpd_req_t *req)
{
    if (!authorized(req)) {
        return deny(req);
    }

    char body[256];
    if (read_body(req, body, sizeof(body)) == 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "empty body");
        return ESP_FAIL;
    }

    int length = 16;
    bool upper = true, lower = true, digits = true, symbols = false;
    json_get_int_field(body, "length", &length);
    json_get_bool_field(body, "upper", &upper);
    json_get_bool_field(body, "lower", &lower);
    json_get_bool_field(body, "digits", &digits);
    json_get_bool_field(body, "symbols", &symbols);

    if (length < 4) length = 4;
    if (length > 128) length = 128;

    char password[129];
    if (vault_generate_password(password, (size_t)length + 1, upper, lower, digits, symbols) != ESP_OK) {
        return send_json_resp(req, "{\"ok\":false,\"error\":\"generate failed\"}");
    }

    char esc[sizeof(password) * 2 + 1];
    json_escape_str(esc, sizeof(esc), password);
    vault_secure_zero(password, sizeof(password));

    char resp[sizeof(esc) + 32];
    snprintf(resp, sizeof(resp), "{\"ok\":true,\"password\":\"%s\"}", esc);
    vault_secure_zero(esc, sizeof(esc));

    esp_err_t ret = send_json_resp(req, resp);
    vault_secure_zero(resp, sizeof(resp));
    return ret;
}

/* POST /api/lock
 * 刻意不做鉴权：锁定只会让设备更安全，任何时刻都允许"应急上锁"，
 * 攻击者即便反复调用也只能让用户重新输入主密码。 */
static esp_err_t handler_lock(httpd_req_t *req)
{
    vault_lock();
    return send_json_resp(req, "{\"ok\":true}");
}

/* POST /api/chpwd {old,new} —— 修改主密码（需已解锁，会重新加密全部条目） */
static esp_err_t handler_change_password(httpd_req_t *req)
{
    int64_t req_start_us = esp_timer_get_time();

    if (!authorized(req)) {
        return deny(req);
    }

    /* ── 硬件安全 2FA：物理按键授权确认 ──
     * 修改主密码属于敏感安全变更，必须经由操作者在物理设备上轻按 [BOOT] 键确认 */
    if (!wait_for_physical_button(req_start_us, 15000)) {
        return send_json_resp(req, "{\"ok\":false,\"error\":\"硬件确认超时：请在 15 秒内轻按开发板上的 [BOOT] 键以授权修改主密码\"}");
    }

    char body[1024];
    if (read_body(req, body, sizeof(body)) == 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "empty body");
        return ESP_FAIL;
    }

    char old_pw[256], new_pw[256];
    if (!json_get_str_field(body, "old", old_pw, sizeof(old_pw))) {
        return send_json_resp(req, "{\"ok\":false,\"error\":\"missing old\"}");
    }
    if (!json_get_str_field(body, "new", new_pw, sizeof(new_pw))) {
        vault_secure_zero(old_pw, sizeof(old_pw));
        return send_json_resp(req, "{\"ok\":false,\"error\":\"missing new\"}");
    }

    char token[VAULT_SESSION_TOKEN_LEN];
    esp_err_t err = vault_change_password(old_pw, new_pw, token, sizeof(token));
    vault_secure_zero(old_pw, sizeof(old_pw));
    vault_secure_zero(new_pw, sizeof(new_pw));
    vault_secure_zero(body, sizeof(body));

    if (err != ESP_OK) {
        char resp[128];
        snprintf(resp, sizeof(resp), "{\"ok\":false,\"error\":\"修改失败 (%d)\"}", err);
        return send_json_resp(req, resp);
    }

    char resp[128];
    snprintf(resp, sizeof(resp), "{\"ok\":true,\"token\":\"%s\"}", token);
    return send_json_resp(req, resp);
}

/* POST /api/export —— 导出加密备份（base64）。
 * 内容是密文+salt+验证块，不含主密码，离线保存也解不开。 */
static esp_err_t handler_export(httpd_req_t *req)
{
    int64_t req_start_us = esp_timer_get_time();

    if (!authorized(req)) {
        return deny(req);
    }

    /* ── 硬件安全 2FA：物理按键授权确认 ──
     * 导出全量加密备份必须经由操作者在物理设备上轻按 [BOOT] 键确认，
     * 杜绝后台恶意脚本静默拖库备份并进行离线爆破。 */
    if (!wait_for_physical_button(req_start_us, 15000)) {
        return send_json_resp(req, "{\"ok\":false,\"error\":\"硬件确认超时：请在 15 秒内轻按开发板上的 [BOOT] 键以授权导出备份\"}");
    }

    uint8_t *bin = NULL;
    size_t bin_len = 0;
    if (vault_export(&bin, &bin_len) != ESP_OK || bin == NULL) {
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"导出失败\"}");
        return ESP_OK;
    }

    /* 先探测长度再编码，避免按最坏情况过度分配 */
    size_t b64_len = 0;
    mbedtls_base64_encode(NULL, 0, &b64_len, bin, bin_len);
    char *b64 = malloc(b64_len + 1);
    if (!b64) {
        vault_secure_zero(bin, bin_len);
        free(bin);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "oom");
        return ESP_FAIL;
    }
    int ret = mbedtls_base64_encode((unsigned char *)b64, b64_len + 1, &b64_len, bin, bin_len);
    vault_secure_zero(bin, bin_len);
    free(bin);
    if (ret != 0) {
        free(b64);
        httpd_resp_set_type(req, "application/json");
        httpd_resp_sendstr(req, "{\"ok\":false,\"error\":\"编码失败\"}");
        return ESP_OK;
    }

    /* base64 字符集不含引号与反斜杠，可直接拼进 JSON；分块发送避免再拷贝一份 */
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send_chunk(req, "{\"ok\":true,\"backup\":\"", HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, b64, b64_len);
    httpd_resp_send_chunk(req, "\"}", HTTPD_RESP_USE_STRLEN);
    esp_err_t send_err = httpd_resp_send_chunk(req, NULL, 0);
    free(b64);
    return send_err;
}

/* POST /api/import {backup,password} —— 用备份整库覆盖（需先校验主密码） */
static esp_err_t handler_import(httpd_req_t *req)
{
    int64_t req_start_us = esp_timer_get_time();

    if (!authorized(req)) {
        return deny(req);
    }

    /* ── 硬件安全 2FA：物理按键授权确认 ──
     * 恢复/覆盖全库属于高危破坏性操作，必须经由操作者在物理设备上轻按 [BOOT] 键确认 */
    if (!wait_for_physical_button(req_start_us, 15000)) {
        return send_json_resp(req, "{\"ok\":false,\"error\":\"硬件确认超时：请在 15 秒内轻按开发板上的 [BOOT] 键以授权恢复备份\"}");
    }

    size_t clen = req->content_len;
    if (clen == 0 || clen > IMPORT_MAX_BODY) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad size");
        return ESP_FAIL;
    }

    char *body = malloc(clen + 1);
    char *bin = NULL;
    if (!body) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "oom");
        return ESP_FAIL;
    }
    size_t got = 0;
    while (got < clen) {
        int n = httpd_req_recv(req, body + got, clen - got);
        if (n <= 0) break;
        got += (size_t)n;
    }
    body[got] = '\0';

    char password[256];
    const char *b64_start = NULL;
    size_t b64_len = 0;
    esp_err_t err = ESP_OK;
    size_t bin_len = 0;

    if (got == 0) {
        err = ESP_ERR_INVALID_SIZE;
    } else if (!json_locate_str_field(body, "backup", &b64_start, &b64_len)) {
        err = ESP_ERR_INVALID_ARG;
    } else if (!json_get_str_field(body, "password", password, sizeof(password))) {
        err = ESP_ERR_INVALID_ARG;
    } else {
        /* 原地定位的 base64 直接解码，不再复制一份到中间缓冲 */
        int ret = mbedtls_base64_decode(NULL, 0, &bin_len,
                                        (const unsigned char *)b64_start, b64_len);
        if (ret != 0 && ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
            err = ESP_ERR_INVALID_ARG;
        } else {
            bin = malloc(bin_len ? bin_len : 1);
            if (!bin) {
                err = ESP_ERR_NO_MEM;
            } else {
                ret = mbedtls_base64_decode((unsigned char *)bin, bin_len, &bin_len,
                                            (const unsigned char *)b64_start, b64_len);
                err = (ret == 0) ? ESP_OK : ESP_ERR_INVALID_ARG;
            }
        }
    }

    if (err == ESP_OK) {
        err = vault_import((const uint8_t *)bin, bin_len, password);
    }

    if (bin) { vault_secure_zero(bin, bin_len); free(bin); }
    vault_secure_zero(password, sizeof(password));
    free(body);

    if (err == ESP_ERR_INVALID_CRC) {
        return send_json_resp(req, "{\"ok\":false,\"error\":\"备份文件损坏\"}");
    }
    if (err == ESP_ERR_INVALID_STATE) {
        return send_json_resp(req, "{\"ok\":false,\"error\":\"主密码与备份不匹配\"}");
    }
    if (err != ESP_OK) {
        return send_json_resp(req, (err == ESP_ERR_NOT_ALLOWED)
                              ? "{\"ok\":false,\"error\":\"设备处于安全只读保护模式\"}"
                              : "{\"ok\":false,\"error\":\"恢复失败\"}");
    }

    return send_json_resp(req, "{\"ok\":true}");
}

/* POST /api/reset —— 清空全部数据，必须持有有效会话令牌 */
static esp_err_t handler_reset(httpd_req_t *req)
{
    int64_t req_start_us = esp_timer_get_time();

    if (!authorized(req)) {
        return deny(req);
    }

    /* ── 硬件安全 2FA：物理按键授权确认 ──
     * 恢复出厂设置将彻底抹除全部分区数据，必须经由操作者在物理设备上轻按 [BOOT] 键确认 */
    if (!wait_for_physical_button(req_start_us, 15000)) {
        return send_json_resp(req, "{\"ok\":false,\"error\":\"硬件确认超时：请在 15 秒内轻按开发板上的 [BOOT] 键以授权重置设备\"}");
    }

    esp_err_t err = vault_reset();
    char resp[64];
    snprintf(resp, sizeof(resp), "{\"ok\":%s}", err == ESP_OK ? "true" : "false");
    return send_json_resp(req, resp);
}

/* ── KV 存储 API ── */

/* GET /api/kv — 列出所有 key */
static esp_err_t handler_kv_list(httpd_req_t *req)
{
    if (!authorized(req)) {
        return deny(req);
    }

    typedef char kv_key_t[VAULT_MAX_KV_KEY_LEN];
    kv_key_t *keys = malloc(sizeof(kv_key_t) * VAULT_MAX_KV_ENTRIES);
    if (!keys) {
        return send_json_resp(req, "{\"ok\":false,\"error\":\"no_mem\"}");
    }

    int count = 0;
    vault_kv_list(keys, VAULT_MAX_KV_ENTRIES, &count);

    char session_id[E2EE_SESSION_ID_LEN];
    bool is_e2ee = get_e2ee_session(req, session_id, sizeof(session_id));

    if (!is_e2ee) {
        /* 流式输出，key 逐个转义 */
        char esc[VAULT_MAX_KV_KEY_LEN * 2 + 1];
        httpd_resp_set_type(req, "application/json");
        json_chunk(req, "{\"ok\":true,\"keys\":[");
        for (int i = 0; i < count; i++) {
            if (i > 0) json_chunk(req, ",");
            json_chunk(req, "\"");
            json_chunk_escaped(req, keys[i], esc, sizeof(esc));
            json_chunk(req, "\"");
        }
        char tail[32];
        snprintf(tail, sizeof(tail), "],\"count\":%d}", count);
        json_chunk(req, tail);
        vault_secure_zero(keys, sizeof(kv_key_t) * VAULT_MAX_KV_ENTRIES);
        free(keys);
        return httpd_resp_send_chunk(req, NULL, 0);
    }

    /* E2EE 加密输出 */
    size_t est_size = (size_t)count * (VAULT_MAX_KV_KEY_LEN * 2 + 4) + 64;
    if (est_size < 512) est_size = 512;
    char *buf = malloc(est_size);
    if (!buf) {
        vault_secure_zero(keys, sizeof(kv_key_t) * VAULT_MAX_KV_ENTRIES);
        free(keys);
        return send_json_resp(req, "{\"ok\":false,\"error\":\"no_mem\"}");
    }
    size_t offset = snprintf(buf, est_size, "{\"ok\":true,\"keys\":[");
    for (int i = 0; i < count; i++) {
        if (i > 0 && offset < est_size) buf[offset++] = ',';
        char esc[VAULT_MAX_KV_KEY_LEN * 2 + 1];
        json_escape_str(esc, sizeof(esc), keys[i]);
        int item_len = snprintf(buf + offset, est_size - offset, "\"%s\"", esc);
        if (item_len > 0) offset += item_len;
    }
    snprintf(buf + offset, est_size - offset, "],\"count\":%d}", count);
    vault_secure_zero(keys, sizeof(kv_key_t) * VAULT_MAX_KV_ENTRIES);
    free(keys);

    esp_err_t ret = send_json_resp(req, buf);
    free(buf);
    return ret;
}

/* GET /api/kv/<key> — 获取值 */
static esp_err_t handler_kv_get(httpd_req_t *req)
{
    int64_t req_start_us = esp_timer_get_time();

    if (!authorized(req)) {
        return deny(req);
    }

    /* ── 硬件安全 2FA：物理按键授权确认 ──
     * 获取敏感存储值必须经由操作者在物理设备上轻按 [BOOT] 键确认 */
    if (!wait_for_physical_button(req_start_us, 15000)) {
        return send_json_resp(req, "{\"ok\":false,\"error\":\"硬件确认超时：请在 15 秒内轻按开发板上的 [BOOT] 键以授权查看\"}");
    }

    /* 从 URI 提取 key: /api/kv/xxx */
    const char *uri = req->uri;
    const char *prefix = "/api/kv/";
    if (strncmp(uri, prefix, strlen(prefix)) != 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad uri");
        return ESP_FAIL;
    }
    const char *kv_key = uri + strlen(prefix);

    char value[VAULT_MAX_KV_VAL_LEN];
    esp_err_t err = vault_kv_get(kv_key, value, sizeof(value));
    if (err != ESP_OK) {
        return send_json_resp(req, "{\"ok\":false,\"error\":\"not found\"}");
    }

    char esc[VAULT_MAX_KV_VAL_LEN * 2 + 1];
    json_escape_str(esc, sizeof(esc), value);
    vault_secure_zero(value, sizeof(value));

    char resp[sizeof(esc) + 32];
    snprintf(resp, sizeof(resp), "{\"ok\":true,\"value\":\"%s\"}", esc);
    vault_secure_zero(esc, sizeof(esc));

    esp_err_t ret = send_json_resp(req, resp);
    vault_secure_zero(resp, sizeof(resp));
    return ret;
}

/* POST /api/kv {key, value} — 设置 KV */
static esp_err_t handler_kv_set(httpd_req_t *req)
{
    if (!authorized(req)) {
        return deny(req);
    }

    char body[VAULT_MAX_KV_VAL_LEN + 128];
    if (read_body(req, body, sizeof(body)) == 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "empty body");
        return ESP_FAIL;
    }

    char key[VAULT_MAX_KV_KEY_LEN];
    char value[VAULT_MAX_KV_VAL_LEN];
    if (!json_get_str_field(body, "key", key, sizeof(key)) || strlen(key) == 0) {
        return send_json_resp(req, "{\"ok\":false,\"error\":\"missing key\"}");
    }
    if (!json_get_str_field(body, "value", value, sizeof(value))) {
        return send_json_resp(req, "{\"ok\":false,\"error\":\"missing value\"}");
    }

    esp_err_t err = vault_kv_set(key, value);
    vault_secure_zero(value, sizeof(value));

    if (err != ESP_OK) {
        return send_json_resp(req, err == ESP_ERR_NOT_ALLOWED
                           ? "{\"ok\":false,\"error\":\"设备处于安全只读保护模式\"}"
                           : "{\"ok\":false,\"error\":\"写入失败\"}");
    }

    return send_json_resp(req, "{\"ok\":true}");
}

/* POST /api/kv/delete {key} — 删除 KV */
static esp_err_t handler_kv_delete(httpd_req_t *req)
{
    if (!authorized(req)) {
        return deny(req);
    }

    char body[256];
    if (read_body(req, body, sizeof(body)) == 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "empty body");
        return ESP_FAIL;
    }

    char key[VAULT_MAX_KV_KEY_LEN];
    if (!json_get_str_field(body, "key", key, sizeof(key))) {
        return send_json_resp(req, "{\"ok\":false,\"error\":\"missing key\"}");
    }

    esp_err_t err = vault_kv_delete(key);
    char resp[64];
    snprintf(resp, sizeof(resp), "{\"ok\":%s}", err == ESP_OK ? "true" : "false");
    return send_json_resp(req, resp);
}

/* POST /api/hid/arm {type:"cred"|"kv", id:0, key:"xxx"} — 武装单次安全键入 */
static esp_err_t handler_hid_arm(httpd_req_t *req)
{
    if (!authorized(req)) {
        return deny(req);
    }

    char body[512];
    if (read_body(req, body, sizeof(body)) == 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "empty body");
        return ESP_FAIL;
    }

    char type[16];
    if (!json_get_str_field(body, "type", type, sizeof(type))) {
        vault_secure_zero(body, sizeof(body));
        return send_json_resp(req, "{\"ok\":false,\"error\":\"missing type\"}");
    }

    char secret[VAULT_MAX_KV_VAL_LEN];
    char label[VAULT_MAX_NAME_LEN];
    secret[0] = '\0';
    label[0] = '\0';

    if (strcmp(type, "cred") == 0) {
        int idx = -1;
        json_get_int_field(body, "id", &idx);
        if (idx < 0) {
            vault_secure_zero(body, sizeof(body));
            return send_json_resp(req, "{\"ok\":false,\"error\":\"missing id\"}");
        }
        vault_cred_t cred;
        esp_err_t err = vault_get_cred(idx, &cred);
        if (err != ESP_OK) {
            vault_secure_zero(body, sizeof(body));
            return send_json_resp(req, "{\"ok\":false,\"error\":\"not found\"}");
        }
        strncpy(secret, cred.password, sizeof(secret) - 1);
        strncpy(label, cred.name, sizeof(label) - 1);
        vault_secure_zero(&cred, sizeof(cred));
    } else if (strcmp(type, "kv") == 0) {
        char key[VAULT_MAX_KV_KEY_LEN];
        if (!json_get_str_field(body, "key", key, sizeof(key))) {
            vault_secure_zero(body, sizeof(body));
            return send_json_resp(req, "{\"ok\":false,\"error\":\"missing key\"}");
        }
        esp_err_t err = vault_kv_get(key, secret, sizeof(secret));
        if (err != ESP_OK) {
            vault_secure_zero(body, sizeof(body));
            return send_json_resp(req, "{\"ok\":false,\"error\":\"not found\"}");
        }
        strncpy(label, key, sizeof(label) - 1);
    } else {
        vault_secure_zero(body, sizeof(body));
        return send_json_resp(req, "{\"ok\":false,\"error\":\"invalid type\"}");
    }

    vault_secure_zero(body, sizeof(body));

    esp_err_t arm_err = usb_hid_arm(secret, label, 30);
    vault_secure_zero(secret, sizeof(secret));

    if (arm_err != ESP_OK) {
        return send_json_resp(req, "{\"ok\":false,\"error\":\"武装失败\"}");
    }

    char esc_label[VAULT_MAX_NAME_LEN * 2 + 1];
    json_escape_str(esc_label, sizeof(esc_label), label);
    char resp[256];
    snprintf(resp, sizeof(resp), "{\"ok\":true,\"timeout\":30,\"label\":\"%s\"}", esc_label);
    return send_json_resp(req, resp);
}

/* POST /api/hid/disarm — 解除安全键入武装 */
static esp_err_t handler_hid_disarm(httpd_req_t *req)
{
    if (!authorized(req)) {
        return deny(req);
    }
    usb_hid_disarm();
    return send_json_resp(req, "{\"ok\":true}");
}

/* GET /api/hid/status — 查询武装状态 */
static esp_err_t handler_hid_status(httpd_req_t *req)
{
    if (!authorized(req)) {
        return deny(req);
    }
    char label[VAULT_MAX_NAME_LEN];
    int remaining = 0;
    bool armed = usb_hid_get_arm_info(label, sizeof(label), &remaining);
    if (!armed) {
        return send_json_resp(req, "{\"ok\":true,\"armed\":false}");
    }
    char esc_label[VAULT_MAX_NAME_LEN * 2 + 1];
    json_escape_str(esc_label, sizeof(esc_label), label);
    char resp[256];
    snprintf(resp, sizeof(resp), "{\"ok\":true,\"armed\":true,\"remaining\":%d,\"label\":\"%s\"}", remaining, esc_label);
    return send_json_resp(req, resp);
}

/* ── HTTP 服务器 ── */
static void start_http_server(void)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.uri_match_fn = httpd_uri_match_wildcard;
    config.max_uri_handlers = 32;    /* 注册 26 个，余量充裕 */
    config.stack_size = 12288;  /* 增加至 12KB 堆栈，为大并发/深调用链提供充裕余量 */

    if (httpd_start(&s_server, &config) != ESP_OK) {
        ESP_LOGE(TAG, "HTTP 服务器启动失败");
        return;
    }

    const httpd_uri_t uris[] = {
        { .uri = "/",                 .method = HTTP_GET,  .handler = handler_root },
        { .uri = "/api/status",       .method = HTTP_GET,  .handler = handler_status },
        { .uri = "/api/health",       .method = HTTP_GET,  .handler = handler_health },
        { .uri = "/api/e2ee/handshake", .method = HTTP_POST, .handler = handler_e2ee_handshake },
        { .uri = "/api/setup",        .method = HTTP_POST, .handler = handler_setup },
        { .uri = "/api/login",        .method = HTTP_POST, .handler = handler_login },
        { .uri = "/api/creds",        .method = HTTP_GET,  .handler = handler_list_creds },
        { .uri = "/api/creds",        .method = HTTP_POST, .handler = handler_add_cred },
        { .uri = "/api/cred/*",       .method = HTTP_GET,  .handler = handler_get_cred },
        { .uri = "/api/cred/update",  .method = HTTP_POST, .handler = handler_update_cred },
        { .uri = "/api/cred/delete",  .method = HTTP_POST, .handler = handler_delete_cred },
        { .uri = "/api/generate",     .method = HTTP_POST, .handler = handler_generate },
        { .uri = "/api/lock",         .method = HTTP_POST, .handler = handler_lock },
        { .uri = "/api/reset",        .method = HTTP_POST, .handler = handler_reset },
        { .uri = "/api/kv",           .method = HTTP_GET,  .handler = handler_kv_list },
        { .uri = "/api/kv",           .method = HTTP_POST, .handler = handler_kv_set },
        { .uri = "/api/kv/*",         .method = HTTP_GET,  .handler = handler_kv_get },
        { .uri = "/api/kv/delete",    .method = HTTP_POST, .handler = handler_kv_delete },
        { .uri = "/api/hid/arm",      .method = HTTP_POST, .handler = handler_hid_arm },
        { .uri = "/api/hid/disarm",   .method = HTTP_POST, .handler = handler_hid_disarm },
        { .uri = "/api/hid/status",   .method = HTTP_GET,  .handler = handler_hid_status },
        { .uri = "/api/usb",          .method = HTTP_GET,  .handler = handler_usb },
        { .uri = "/api/reboot",       .method = HTTP_POST, .handler = handler_reboot },
        { .uri = "/api/chpwd",        .method = HTTP_POST, .handler = handler_change_password },
        { .uri = "/api/export",       .method = HTTP_POST, .handler = handler_export },
        { .uri = "/api/import",       .method = HTTP_POST, .handler = handler_import },
    };

    for (size_t i = 0; i < sizeof(uris) / sizeof(uris[0]); i++) {
        httpd_register_uri_handler(s_server, &uris[i]);
    }

    ESP_LOGI(TAG, "HTTP 服务器已启动");
}

/* 说明：旧工程依赖 Wi-Fi AP/STA 提供管理通道，本设备全部改为 USB 网络，
 * 因此 Wi-Fi 配置存储、事件处理、AP/STA 启动逻辑一并删除，
 * 网络入口由 usb_net_init() 提供（NCM + RNDIS 双通道 + DHCP Server）。 */

/* ── 入口 ── */
void app_main(void)
{
    ESP_LOGI(TAG, "=== KeyVault 启动初始化 ===");

    /* 系统 NVS */
    esp_err_t nvs_ret = nvs_flash_init();
    if (nvs_ret == ESP_ERR_NVS_NO_FREE_PAGES || nvs_ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        nvs_ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(nvs_ret);

    /* 初始化 Vault（加密存储，双 NVS 分区冗余）与 USB HID */
    ESP_ERROR_CHECK(vault_init());
    ESP_ERROR_CHECK(usb_hid_init());
    ESP_ERROR_CHECK(e2ee_init());

    /* 配置 LED 与 BOOT 按键引脚 */
    gpio_reset_pin(LED_GPIO);
    gpio_set_direction(LED_GPIO, GPIO_MODE_OUTPUT);

    /* 配置 BOOT 按键引脚 (GPIO 0: 必须使用 gpio_config 显式开启输入缓冲与上拉) */
    gpio_config_t btn_cfg = {
        .pin_bit_mask = (1ULL << BOOT_BUTTON_GPIO),
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    gpio_config(&btn_cfg);
    ESP_LOGI(TAG, "BOOT 按键就绪 (GPIO 0 当前电平: %d, 0=按下/1=未按)", gpio_get_level(BOOT_BUTTON_GPIO));

    /* 初始化物理按键 2FA 确认信号量 */
    s_auth_sem = xSemaphoreCreateBinary();

    /* ── 冷启动直入 USB-OTG 原生网卡 ──
     * 立即将芯片内部 PHY 连接至 USB-OTG 控制器，确保开机直接作为原生 USB 网卡与主机枚举，
     * 彻底消除串口停留缓冲期导致的 xHCI 端口挂起与重置超时问题。
     */
    USB_WRAP.otg_conf.phy_sel = 0;
    RTCCNTL.usb_conf.sw_hw_usb_phy_sel = 1;
    RTCCNTL.usb_conf.sw_usb_phy_sel = 1;
    USB_WRAP.otg_conf.pad_enable = 1;

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(usb_net_init());

    /* 启动 HTTP 服务 */
    start_http_server();

    /* 启动后台看护任务（运行期长按 BOOT 键 10 秒开启 Wi-Fi + LED 状态指示 + USB 拔插自锁） */
    xTaskCreate(monitor_task, "monitor", 3072, NULL, 5, NULL);

    ESP_LOGI(TAG, "KeyVault 就绪：主机获取 IP 后访问 http://%s（任意时刻长按 BOOT 键 10 秒可激活应急 Wi-Fi）", KEYVAULT_IP_ADDR);
}
