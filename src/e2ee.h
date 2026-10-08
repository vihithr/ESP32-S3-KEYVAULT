/*
 * e2ee.h —— KeyVault 全链路端到端加密（E2EE）管道
 *
 * 架构：
 *   - 密钥协商: Ephemeral X25519 (ECDH, RFC 7748)
 *   - 密钥派生: SHA-256(shared_secret) -> 256-bit Session Key
 *   - 载荷加密: 芯片硬件加速 AES-256-GCM (12-byte IV, 16-byte Tag)
 *   - 浏览器端: 纯原生轻量 JS 实现，零 HTTPS 依赖，彻底绕过 Secure Context 限制
 */

#pragma once

#include "esp_err.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define E2EE_PUBKEY_LEN      32
#define E2EE_KEY_LEN         32
#define E2EE_IV_LEN          12
#define E2EE_TAG_LEN         16
#define E2EE_SESSION_ID_LEN  17  /* 16 hex chars + null */

#ifdef __cplusplus
extern "C" {
#endif

/* 初始化 E2EE 模块 */
esp_err_t e2ee_init(void);

/* 处理客户端握手：
 * client_pub_hex: 客户端公钥 (64 字符十六进制)
 * server_pub_hex_out: 服务端临时公钥 (至少 65 字节缓冲)
 * session_id_out: 分配的会话 ID (至少 17 字节缓冲)
 */
esp_err_t e2ee_handshake(const char *client_pub_hex, char *server_pub_hex_out,
                         char *session_id_out, size_t session_id_len);

/* 验证会话 ID 是否有效并刷新活跃时间 */
bool e2ee_is_session_valid(const char *session_id);

/* 解密请求密文负载：
 * iv_hex, tag_hex, cipher_hex: 十六进制字符串
 * plain_out: 解密后的明文字符串缓冲区（调用方传入）
 * max_plain: plain_out 容量
 */
esp_err_t e2ee_decrypt(const char *session_id,
                       const char *iv_hex, const char *tag_hex, const char *cipher_hex,
                       uint8_t *plain_out, size_t max_plain, size_t *plain_len_out);

/* 加密响应载荷：
 * plain: 明文字符串
 * plain_len: 明文长度
 * json_resp_out: 输出组装好的 JSON，如 {"ok":true,"iv":"...","tag":"...","data":"..."}
 * max_resp: json_resp_out 容量
 */
esp_err_t e2ee_encrypt_json_resp(const char *session_id,
                                 const uint8_t *plain, size_t plain_len,
                                 char *json_resp_out, size_t max_resp);

#ifdef __cplusplus
}
#endif
