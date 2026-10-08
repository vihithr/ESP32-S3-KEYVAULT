/*
 * e2ee.c —— KeyVault 全链路端到端加密（E2EE）实现
 *
 * 架构：
 *   - Ephemeral X25519 (ECDH, RFC 7748)
 *   - SHA-256 密钥派生
 *   - 硬件加速 AES-256-GCM
 */

#include "e2ee.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "mbedtls/sha256.h"
#include "mbedtls/gcm.h"

#define TAG "E2EE"

#define MAX_E2EE_SESSIONS 8
#define E2EE_SESSION_TIMEOUT_US (10LL * 60 * 1000 * 1000) /* 10 分钟会话过期 */

typedef struct {
    char     session_id[E2EE_SESSION_ID_LEN];
    uint8_t  session_key[E2EE_KEY_LEN];
    int64_t  last_used_us;
    bool     active;
} e2ee_session_entry_t;

static e2ee_session_entry_t s_sessions[MAX_E2EE_SESSIONS];
static SemaphoreHandle_t    s_e2ee_mutex = NULL;

#define E2EE_LOCK()   do { if (s_e2ee_mutex) xSemaphoreTake(s_e2ee_mutex, portMAX_DELAY); } while (0)
#define E2EE_UNLOCK() do { if (s_e2ee_mutex) xSemaphoreGive(s_e2ee_mutex); } while (0)

static void e2ee_secure_zero(void *p, size_t n)
{
    volatile uint8_t *vp = (volatile uint8_t *)p;
    while (n--) *vp++ = 0;
}

/* ── Hex 转换辅助 ── */

static int hex2byte(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static bool hex2bin(const char *hex, size_t hex_len, uint8_t *bin, size_t max_bin, size_t *out_bin_len)
{
    if (hex_len % 2 != 0 || hex_len / 2 > max_bin) return false;
    for (size_t i = 0; i < hex_len; i += 2) {
        int h = hex2byte(hex[i]);
        int l = hex2byte(hex[i + 1]);
        if (h < 0 || l < 0) return false;
        bin[i / 2] = (uint8_t)((h << 4) | l);
    }
    *out_bin_len = hex_len / 2;
    return true;
}

static void bin2hex(const uint8_t *bin, size_t bin_len, char *hex, size_t max_hex)
{
    if (bin_len * 2 + 1 > max_hex) return;
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < bin_len; i++) {
        hex[i * 2]     = digits[(bin[i] >> 4) & 0x0F];
        hex[i * 2 + 1] = digits[bin[i] & 0x0F];
    }
    hex[bin_len * 2] = '\0';
}

/* ── RFC 7748 Curve25519 标量乘法 (TweetNaCl) ── */

typedef int64_t gf[16];

static const uint8_t _9[32] = {9}; /* Curve25519 基点 */

static void car25519(gf o)
{
    for (int i = 0; i < 16; ++i) {
        o[i] += (1LL << 16);
        int64_t c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

static void sel25519(gf p, gf q, int b)
{
    int64_t t, c = ~(b - 1);
    for (int i = 0; i < 16; ++i) {
        t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void pack25519(uint8_t *o, const gf n)
{
    int i, j;
    gf m, t;
    for (i = 0; i < 16; ++i) t[i] = n[i];
    car25519(t); car25519(t); car25519(t);
    for (j = 0; j < 2; ++j) {
        m[0] = t[0] - 0xffed;
        for (i = 1; i < 15; ++i) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        m[14] &= 0xffff;
        int64_t b = (m[15] >> 16) & 1;
        m[15] &= 0xffff;
        sel25519(t, m, 1 - (int)b);
    }
    for (i = 0; i < 16; ++i) {
        o[2 * i]     = (uint8_t)(t[i] & 0xff);
        o[2 * i + 1] = (uint8_t)(t[i] >> 8);
    }
}

static void unpack25519(gf o, const uint8_t *n)
{
    for (int i = 0; i < 16; ++i) o[i] = n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
}

static void A(gf o, const gf a, const gf b)
{
    for (int i = 0; i < 16; ++i) o[i] = a[i] + b[i];
}

static void Z(gf o, const gf a, const gf b)
{
    for (int i = 0; i < 16; ++i) o[i] = a[i] - b[i];
}

static void M(gf o, const gf a, const gf b)
{
    int64_t t[31] = {0};
    for (int i = 0; i < 16; ++i) {
        for (int j = 0; j < 16; ++j) {
            t[i + j] += a[i] * b[j];
        }
    }
    for (int i = 0; i < 15; ++i) t[i] += 38 * t[i + 16];
    for (int i = 0; i < 16; ++i) o[i] = t[i];
    car25519(o); car25519(o);
}

static void S(gf o, const gf a)
{
    M(o, a, a);
}

static void inv25519(gf o, const gf i)
{
    gf c;
    for (int a = 0; a < 16; ++a) c[a] = i[a];
    for (int a = 253; a >= 0; --a) {
        S(c, c);
        if (a != 2 && a != 4) M(c, c, i);
    }
    for (int a = 0; a < 16; ++a) o[a] = c[a];
}

static int crypto_scalarmult(uint8_t *q, const uint8_t *n, const uint8_t *p)
{
    uint8_t z[32];
    int64_t r;
    gf x, a, b, c, d, e, f;
    for (int i = 0; i < 31; ++i) z[i] = n[i];
    z[31] = (n[31] & 127) | 64;
    z[0] &= 248;
    unpack25519(x, p);
    for (int i = 0; i < 16; ++i) {
        b[i] = x[i]; d[i] = a[i] = c[i] = 0;
    }
    a[0] = d[0] = 1;
    for (int i = 254; i >= 0; --i) {
        r = (z[i / 8] >> (i & 7)) & 1;
        sel25519(a, b, r);
        sel25519(c, d, r);
        A(e, a, c);
        Z(a, a, c);
        A(c, b, d);
        Z(b, b, d);
        S(d, e);
        S(f, a);
        M(a, c, a);
        M(c, b, e);
        A(e, a, c);
        Z(a, a, c);
        S(b, a);
        Z(c, d, f);
        const int64_t a24[16] = {121665, 0};
        M(a, c, a24);
        A(a, a, d);
        M(c, c, a);
        M(a, d, f);
        M(d, b, x);
        S(b, e);
        sel25519(a, b, r);
        sel25519(c, d, r);
    }
    inv25519(c, c);
    M(a, a, c);
    pack25519(q, a);
    return 0;
}

/* ── 会话查找与清理 ── */

static e2ee_session_entry_t *find_session(const char *session_id)
{
    if (!session_id || strlen(session_id) != 16) return NULL;
    int64_t now = esp_timer_get_time();
    for (int i = 0; i < MAX_E2EE_SESSIONS; i++) {
        if (s_sessions[i].active && strcmp(s_sessions[i].session_id, session_id) == 0) {
            if (now - s_sessions[i].last_used_us > E2EE_SESSION_TIMEOUT_US) {
                /* 超时注销 */
                s_sessions[i].active = false;
                e2ee_secure_zero(s_sessions[i].session_key, E2EE_KEY_LEN);
                return NULL;
            }
            s_sessions[i].last_used_us = now;
            return &s_sessions[i];
        }
    }
    return NULL;
}

static e2ee_session_entry_t *allocate_session(void)
{
    int64_t now = esp_timer_get_time();
    int lru_idx = 0;
    int64_t oldest = INT64_MAX;

    for (int i = 0; i < MAX_E2EE_SESSIONS; i++) {
        if (!s_sessions[i].active || (now - s_sessions[i].last_used_us > E2EE_SESSION_TIMEOUT_US)) {
            s_sessions[i].active = false;
            e2ee_secure_zero(s_sessions[i].session_key, E2EE_KEY_LEN);
            return &s_sessions[i];
        }
        if (s_sessions[i].last_used_us < oldest) {
            oldest = s_sessions[i].last_used_us;
            lru_idx = i;
        }
    }

    /* 驱逐最旧会话 */
    s_sessions[lru_idx].active = false;
    e2ee_secure_zero(s_sessions[lru_idx].session_key, E2EE_KEY_LEN);
    return &s_sessions[lru_idx];
}

/* ── 公开 API ── */

esp_err_t e2ee_init(void)
{
    if (s_e2ee_mutex == NULL) {
        s_e2ee_mutex = xSemaphoreCreateMutex();
        if (s_e2ee_mutex == NULL) return ESP_FAIL;
    }
    memset(s_sessions, 0, sizeof(s_sessions));
    ESP_LOGI(TAG, "E2EE 模块初始化完成 (X25519 + AES-256-GCM 硬件加速)");
    return ESP_OK;
}

esp_err_t e2ee_handshake(const char *client_pub_hex, char *server_pub_hex_out,
                         char *session_id_out, size_t session_id_len)
{
    if (!client_pub_hex || strlen(client_pub_hex) != 64 || !server_pub_hex_out || !session_id_out) {
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t c_pub[E2EE_PUBKEY_LEN];
    size_t bin_len = 0;
    if (!hex2bin(client_pub_hex, 64, c_pub, sizeof(c_pub), &bin_len) || bin_len != 32) {
        return ESP_ERR_INVALID_ARG;
    }

    /* 1. 生成服务端临时密钥对 */
    uint8_t s_priv[32];
    uint8_t s_pub[32];
    esp_fill_random(s_priv, 32);
    s_priv[0]  &= 248;
    s_priv[31] &= 127;
    s_priv[31] |= 64;

    crypto_scalarmult(s_pub, s_priv, _9);

    /* 2. 计算共享秘钥 */
    uint8_t shared_secret[32];
    crypto_scalarmult(shared_secret, s_priv, c_pub);
    e2ee_secure_zero(s_priv, sizeof(s_priv));

    /* 检查是否为弱共享秘钥（全 0） */
    uint8_t zero_acc = 0;
    for (int i = 0; i < 32; i++) zero_acc |= shared_secret[i];
    if (zero_acc == 0) {
        ESP_LOGE(TAG, "检测到弱 ECDH 共享秘密，握手拒绝");
        return ESP_ERR_INVALID_STATE;
    }

    /* 3. 派生会话密钥: session_key = SHA256(shared_secret) */
    uint8_t session_key[32];
    mbedtls_sha256(shared_secret, 32, session_key, 0);
    e2ee_secure_zero(shared_secret, sizeof(shared_secret));

    /* 4. 分配会话记录并保存 */
    E2EE_LOCK();
    e2ee_session_entry_t *s = allocate_session();
    uint8_t rand_id[8];
    esp_fill_random(rand_id, sizeof(rand_id));
    bin2hex(rand_id, sizeof(rand_id), s->session_id, sizeof(s->session_id));
    memcpy(s->session_key, session_key, 32);
    s->last_used_us = esp_timer_get_time();
    s->active = true;

    bin2hex(s_pub, 32, server_pub_hex_out, 65);
    strlcpy(session_id_out, s->session_id, session_id_len);
    E2EE_UNLOCK();

    e2ee_secure_zero(session_key, sizeof(session_key));
    ESP_LOGI(TAG, "E2EE 握手成功，会话 ID: %s", session_id_out);
    return ESP_OK;
}

bool e2ee_is_session_valid(const char *session_id)
{
    E2EE_LOCK();
    bool valid = (find_session(session_id) != NULL);
    E2EE_UNLOCK();
    return valid;
}

esp_err_t e2ee_decrypt(const char *session_id,
                       const char *iv_hex, const char *tag_hex, const char *cipher_hex,
                       uint8_t *plain_out, size_t max_plain, size_t *plain_len_out)
{
    if (!session_id || !iv_hex || !tag_hex || !cipher_hex || !plain_out || !plain_len_out) {
        return ESP_ERR_INVALID_ARG;
    }

    size_t iv_hex_len = strlen(iv_hex);
    size_t tag_hex_len = strlen(tag_hex);
    size_t cipher_hex_len = strlen(cipher_hex);
    if (iv_hex_len != 24 || tag_hex_len != 32 || (cipher_hex_len % 2 != 0)) {
        return ESP_ERR_INVALID_ARG;
    }
    size_t cipher_len = cipher_hex_len / 2;
    if (cipher_len > max_plain) {
        return ESP_ERR_INVALID_SIZE;
    }

    uint8_t iv[E2EE_IV_LEN];
    uint8_t tag[E2EE_TAG_LEN];
    uint8_t *cipher = malloc(cipher_len);
    if (!cipher && cipher_len > 0) return ESP_ERR_NO_MEM;

    size_t blen = 0;
    if (!hex2bin(iv_hex, 24, iv, sizeof(iv), &blen) ||
        !hex2bin(tag_hex, 32, tag, sizeof(tag), &blen) ||
        (cipher_len > 0 && !hex2bin(cipher_hex, cipher_hex_len, cipher, cipher_len, &blen))) {
        free(cipher);
        return ESP_ERR_INVALID_ARG;
    }

    E2EE_LOCK();
    e2ee_session_entry_t *s = find_session(session_id);
    if (!s) {
        E2EE_UNLOCK();
        free(cipher);
        return ESP_ERR_NOT_FOUND;
    }

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, s->session_key, 256);
    if (ret != 0) {
        mbedtls_gcm_free(&gcm);
        E2EE_UNLOCK();
        free(cipher);
        return ESP_FAIL;
    }

    ret = mbedtls_gcm_auth_decrypt(&gcm, cipher_len,
                                    iv, E2EE_IV_LEN,
                                    NULL, 0,
                                    tag, E2EE_TAG_LEN,
                                    cipher, plain_out);
    mbedtls_gcm_free(&gcm);
    E2EE_UNLOCK();
    free(cipher);

    if (ret != 0) {
        ESP_LOGW(TAG, "E2EE 解密认证失败 (tag 校验未通过: %d)", ret);
        return ESP_ERR_INVALID_STATE;
    }

    plain_out[cipher_len] = '\0';
    *plain_len_out = cipher_len;
    return ESP_OK;
}

esp_err_t e2ee_encrypt_json_resp(const char *session_id,
                                 const uint8_t *plain, size_t plain_len,
                                 char *json_resp_out, size_t max_resp)
{
    if (!session_id || !plain || !json_resp_out) return ESP_ERR_INVALID_ARG;

    E2EE_LOCK();
    e2ee_session_entry_t *s = find_session(session_id);
    if (!s) {
        E2EE_UNLOCK();
        return ESP_ERR_NOT_FOUND;
    }

    uint8_t iv[E2EE_IV_LEN];
    uint8_t tag[E2EE_TAG_LEN];
    esp_fill_random(iv, E2EE_IV_LEN);

    uint8_t *cipher = malloc(plain_len);
    if (!cipher && plain_len > 0) {
        E2EE_UNLOCK();
        return ESP_ERR_NO_MEM;
    }

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, s->session_key, 256);
    if (ret == 0) {
        ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plain_len,
                                         iv, E2EE_IV_LEN,
                                         NULL, 0,
                                         plain, cipher,
                                         E2EE_TAG_LEN, tag);
    }
    mbedtls_gcm_free(&gcm);
    E2EE_UNLOCK();

    if (ret != 0) {
        free(cipher);
        return ESP_FAIL;
    }

    char iv_hex[25];
    char tag_hex[33];
    bin2hex(iv, E2EE_IV_LEN, iv_hex, sizeof(iv_hex));
    bin2hex(tag, E2EE_TAG_LEN, tag_hex, sizeof(tag_hex));

    size_t cipher_hex_len = plain_len * 2;
    char *cipher_hex = malloc(cipher_hex_len + 1);
    if (!cipher_hex) {
        free(cipher);
        return ESP_ERR_NO_MEM;
    }
    bin2hex(cipher, plain_len, cipher_hex, cipher_hex_len + 1);
    free(cipher);

    int written = snprintf(json_resp_out, max_resp,
                           "{\"ok\":true,\"e2ee\":true,\"iv\":\"%s\",\"tag\":\"%s\",\"data\":\"%s\"}",
                           iv_hex, tag_hex, cipher_hex);
    free(cipher_hex);

    if (written < 0 || (size_t)written >= max_resp) {
        return ESP_ERR_INVALID_SIZE;
    }
    return ESP_OK;
}
