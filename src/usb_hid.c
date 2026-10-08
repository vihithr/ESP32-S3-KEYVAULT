/*
 * usb_hid.c —— KeyVault USB HID 免驱硬件模拟键盘驱动与单次武装状态机
 */
#include "usb_hid.h"
#include "keyvault.h"

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_timer.h"
#include "esp_log.h"

#include "tusb.h"
#include "class/hid/hid_device.h"
#include "class/hid/hid.h"

static const char *TAG = "usb_hid";

typedef struct {
    bool armed;
    int64_t expire_us;
    char secret[VAULT_MAX_KV_VAL_LEN];
    char label[VAULT_MAX_NAME_LEN];
} hid_arm_state_t;

static hid_arm_state_t s_arm;
static portMUX_TYPE s_hid_lock = portMUX_INITIALIZER_UNLOCKED;

esp_err_t usb_hid_init(void)
{
    portENTER_CRITICAL(&s_hid_lock);
    s_arm.armed = false;
    s_arm.expire_us = 0;
    vault_secure_zero(s_arm.secret, sizeof(s_arm.secret));
    s_arm.label[0] = '\0';
    portEXIT_CRITICAL(&s_hid_lock);
    ESP_LOGI(TAG, "USB HID 键盘子系统已就绪");
    return ESP_OK;
}

bool usb_hid_is_ready(void)
{
    return tud_hid_ready();
}

static bool ascii_to_hid(char c, uint8_t *mod_out, uint8_t *key_out)
{
    if (c >= 'a' && c <= 'z') {
        *mod_out = 0;
        *key_out = HID_KEY_A + (uint8_t)(c - 'a');
        return true;
    }
    if (c >= 'A' && c <= 'Z') {
        *mod_out = KEYBOARD_MODIFIER_LEFTSHIFT;
        *key_out = HID_KEY_A + (uint8_t)(c - 'A');
        return true;
    }
    if (c >= '1' && c <= '9') {
        *mod_out = 0;
        *key_out = HID_KEY_1 + (uint8_t)(c - '1');
        return true;
    }
    if (c == '0') {
        *mod_out = 0;
        *key_out = HID_KEY_0;
        return true;
    }

    *mod_out = 0;
    switch (c) {
        case ' ':  *key_out = HID_KEY_SPACE; return true;
        case '\t': *key_out = HID_KEY_TAB; return true;
        case '-':  *key_out = HID_KEY_MINUS; return true;
        case '=':  *key_out = HID_KEY_EQUAL; return true;
        case '[':  *key_out = HID_KEY_BRACKET_LEFT; return true;
        case ']':  *key_out = HID_KEY_BRACKET_RIGHT; return true;
        case '\\': *key_out = HID_KEY_BACKSLASH; return true;
        case ';':  *key_out = HID_KEY_SEMICOLON; return true;
        case '\'': *key_out = HID_KEY_APOSTROPHE; return true;
        case '`':  *key_out = HID_KEY_GRAVE; return true;
        case ',':  *key_out = HID_KEY_COMMA; return true;
        case '.':  *key_out = HID_KEY_PERIOD; return true;
        case '/':  *key_out = HID_KEY_SLASH; return true;

        /* 带 Shift 修饰键的标点符号 */
        case '!':  *mod_out = KEYBOARD_MODIFIER_LEFTSHIFT; *key_out = HID_KEY_1; return true;
        case '@':  *mod_out = KEYBOARD_MODIFIER_LEFTSHIFT; *key_out = HID_KEY_2; return true;
        case '#':  *mod_out = KEYBOARD_MODIFIER_LEFTSHIFT; *key_out = HID_KEY_3; return true;
        case '$':  *mod_out = KEYBOARD_MODIFIER_LEFTSHIFT; *key_out = HID_KEY_4; return true;
        case '%':  *mod_out = KEYBOARD_MODIFIER_LEFTSHIFT; *key_out = HID_KEY_5; return true;
        case '^':  *mod_out = KEYBOARD_MODIFIER_LEFTSHIFT; *key_out = HID_KEY_6; return true;
        case '&':  *mod_out = KEYBOARD_MODIFIER_LEFTSHIFT; *key_out = HID_KEY_7; return true;
        case '*':  *mod_out = KEYBOARD_MODIFIER_LEFTSHIFT; *key_out = HID_KEY_8; return true;
        case '(':  *mod_out = KEYBOARD_MODIFIER_LEFTSHIFT; *key_out = HID_KEY_9; return true;
        case ')':  *mod_out = KEYBOARD_MODIFIER_LEFTSHIFT; *key_out = HID_KEY_0; return true;
        case '_':  *mod_out = KEYBOARD_MODIFIER_LEFTSHIFT; *key_out = HID_KEY_MINUS; return true;
        case '+':  *mod_out = KEYBOARD_MODIFIER_LEFTSHIFT; *key_out = HID_KEY_EQUAL; return true;
        case '{':  *mod_out = KEYBOARD_MODIFIER_LEFTSHIFT; *key_out = HID_KEY_BRACKET_LEFT; return true;
        case '}':  *mod_out = KEYBOARD_MODIFIER_LEFTSHIFT; *key_out = HID_KEY_BRACKET_RIGHT; return true;
        case '|':  *mod_out = KEYBOARD_MODIFIER_LEFTSHIFT; *key_out = HID_KEY_BACKSLASH; return true;
        case ':':  *mod_out = KEYBOARD_MODIFIER_LEFTSHIFT; *key_out = HID_KEY_SEMICOLON; return true;
        case '"':  *mod_out = KEYBOARD_MODIFIER_LEFTSHIFT; *key_out = HID_KEY_APOSTROPHE; return true;
        case '~':  *mod_out = KEYBOARD_MODIFIER_LEFTSHIFT; *key_out = HID_KEY_GRAVE; return true;
        case '<':  *mod_out = KEYBOARD_MODIFIER_LEFTSHIFT; *key_out = HID_KEY_COMMA; return true;
        case '>':  *mod_out = KEYBOARD_MODIFIER_LEFTSHIFT; *key_out = HID_KEY_PERIOD; return true;
        case '?':  *mod_out = KEYBOARD_MODIFIER_LEFTSHIFT; *key_out = HID_KEY_SLASH; return true;

        default:
            return false;
    }
}

bool usb_hid_send_char(char c)
{
    uint8_t mod = 0;
    uint8_t key = 0;
    if (!ascii_to_hid(c, &mod, &key)) {
        ESP_LOGW(TAG, "未知/不支持的击键字符: 0x%02X (%c)", (unsigned char)c, c);
        return false;
    }

    uint8_t keycodes[6] = { key, 0, 0, 0, 0, 0 };

    /* 1. 等待 HID 端点空闲准备 */
    int wait_ticks = 0;
    while (!tud_hid_ready() && wait_ticks < 15) {
        vTaskDelay(pdMS_TO_TICKS(10));
        wait_ticks++;
    }
    if (!tud_hid_ready()) {
        ESP_LOGW(TAG, "HID 端点忙，跳过字符 %c", c);
        return false;
    }

    /* 2. 发送按键按下报表 */
    tud_hid_keyboard_report(0, mod, keycodes);
    vTaskDelay(pdMS_TO_TICKS(12));

    /* 3. 等待端点空闲 */
    wait_ticks = 0;
    while (!tud_hid_ready() && wait_ticks < 15) {
        vTaskDelay(pdMS_TO_TICKS(10));
        wait_ticks++;
    }

    /* 4. 发送按键释放报表 (全零) */
    uint8_t empty_keys[6] = {0};
    tud_hid_keyboard_report(0, 0, empty_keys);
    vTaskDelay(pdMS_TO_TICKS(12));

    return true;
}

bool usb_hid_type_string(const char *str)
{
    if (!str) return false;

    /* 初始轻微延时 60ms，防止按键机械抖动与主机操作系统输入焦点尚未就绪 */
    vTaskDelay(pdMS_TO_TICKS(60));

    while (*str) {
        usb_hid_send_char(*str);
        str++;
    }

    /* 严格不发送 Enter！按键直接结束，不触发提交 */
    return true;
}

esp_err_t usb_hid_arm(const char *secret, const char *label, uint32_t timeout_sec)
{
    if (!secret || strlen(secret) == 0) return ESP_ERR_INVALID_ARG;

    portENTER_CRITICAL(&s_hid_lock);
    s_arm.armed = true;
    s_arm.expire_us = esp_timer_get_time() + ((int64_t)timeout_sec * 1000000LL);
    strncpy(s_arm.secret, secret, sizeof(s_arm.secret) - 1);
    s_arm.secret[sizeof(s_arm.secret) - 1] = '\0';
    if (label) {
        strncpy(s_arm.label, label, sizeof(s_arm.label) - 1);
        s_arm.label[sizeof(s_arm.label) - 1] = '\0';
    } else {
        s_arm.label[0] = '\0';
    }
    portEXIT_CRITICAL(&s_hid_lock);

    ESP_LOGI(TAG, "已武装硬件安全键入: 条目='%s', 超时=%u 秒", s_arm.label, (unsigned)timeout_sec);
    return ESP_OK;
}

void usb_hid_disarm(void)
{
    portENTER_CRITICAL(&s_hid_lock);
    s_arm.armed = false;
    s_arm.expire_us = 0;
    vault_secure_zero(s_arm.secret, sizeof(s_arm.secret));
    s_arm.label[0] = '\0';
    portEXIT_CRITICAL(&s_hid_lock);
    ESP_LOGI(TAG, "已解除武装并物理抹零暂存内存");
}

bool usb_hid_is_armed(void)
{
    bool is_armed = false;
    portENTER_CRITICAL(&s_hid_lock);
    if (s_arm.armed) {
        if (esp_timer_get_time() > s_arm.expire_us) {
            /* 超时自动失效 */
            s_arm.armed = false;
            s_arm.expire_us = 0;
            vault_secure_zero(s_arm.secret, sizeof(s_arm.secret));
            s_arm.label[0] = '\0';
        } else {
            is_armed = true;
        }
    }
    portEXIT_CRITICAL(&s_hid_lock);
    return is_armed;
}

bool usb_hid_get_arm_info(char *label_out, size_t label_len, int *remaining_sec)
{
    bool is_armed = false;
    portENTER_CRITICAL(&s_hid_lock);
    if (s_arm.armed) {
        int64_t now = esp_timer_get_time();
        if (now > s_arm.expire_us) {
            s_arm.armed = false;
            s_arm.expire_us = 0;
            vault_secure_zero(s_arm.secret, sizeof(s_arm.secret));
            s_arm.label[0] = '\0';
        } else {
            is_armed = true;
            if (remaining_sec) {
                *remaining_sec = (int)((s_arm.expire_us - now) / 1000000LL);
            }
            if (label_out && label_len > 0) {
                strncpy(label_out, s_arm.label, label_len - 1);
                label_out[label_len - 1] = '\0';
            }
        }
    }
    portEXIT_CRITICAL(&s_hid_lock);
    return is_armed;
}

bool usb_hid_trigger(void)
{
    char tmp[VAULT_MAX_KV_VAL_LEN];
    bool should_type = false;

    portENTER_CRITICAL(&s_hid_lock);
    if (s_arm.armed) {
        int64_t now = esp_timer_get_time();
        if (now <= s_arm.expire_us) {
            should_type = true;
            strncpy(tmp, s_arm.secret, sizeof(tmp) - 1);
            tmp[sizeof(tmp) - 1] = '\0';
        }
        /* 单次授权：触发即销毁，防重放 */
        s_arm.armed = false;
        s_arm.expire_us = 0;
        vault_secure_zero(s_arm.secret, sizeof(s_arm.secret));
        s_arm.label[0] = '\0';
    }
    portEXIT_CRITICAL(&s_hid_lock);

    if (!should_type) {
        return false;
    }

    ESP_LOGI(TAG, "物理 [BOOT] 键触发硬件键入！长度: %zu", strlen(tmp));
    bool ok = usb_hid_type_string(tmp);
    vault_secure_zero(tmp, sizeof(tmp)); /* 物理抹零局部栈缓冲区 */
    return ok;
}
