/*
 * usb_hid.h —— KeyVault USB HID 免驱硬件模拟键盘驱动与单次武装状态机
 *
 * 核心特性：
 *   - 硬件直通输入：将密码直接模拟物理击键输入目标窗口，完全不走宿主机剪贴板。
 *   - 严格不带回车 (Enter)：防止在未确认的表单中误触发提前提交。
 *   - 单次武装与防重放：进入武装态后 30 秒有效，由物理 [BOOT] 键触发一次即销毁。
 *   - 物理擦零：键入完毕立即对暂存内存执行 vault_secure_zero。
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 初始化 HID 状态机 */
esp_err_t usb_hid_init(void);

/* 检查 TinyUSB HID 是否挂载并准备好发送报表 */
bool usb_hid_is_ready(void);

/* 单次安全键入武装：暂存 secret 到 RAM 缓冲区，启动倒计时 */
esp_err_t usb_hid_arm(const char *secret, const char *label, uint32_t timeout_sec);

/* 取消武装：清空武装状态并物理抹零缓冲区 */
void usb_hid_disarm(void);

/* 查询当前是否处于武装就绪状态（若已超时则自动 disarm 并返回 false） */
bool usb_hid_is_armed(void);

/* 获取当前武装状态信息（用于 Web API 查询） */
bool usb_hid_get_arm_info(char *label_out, size_t label_len, int *remaining_sec);

/*
 * 由物理 [BOOT] 按键触发硬件安全键入：
 * 若当前处于有效武装态，则将暂存密码模拟键盘逐字敲入目标焦点，
 * 严格不带回车，键入完成后立即擦零内存并解除武装。
 * 成功返回 true，未武装或输入失败返回 false。
 */
bool usb_hid_trigger(void);

/* 字符键入底层接口（支持标准 ASCII） */
bool usb_hid_send_char(char c);

/* 字符串键入底层接口（带按键防丢间隔，严格不带回车） */
bool usb_hid_type_string(const char *str);

#ifdef __cplusplus
}
#endif
