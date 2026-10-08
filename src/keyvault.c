/*
 * keyvault.c —— ESP32 密钥管理工具 · 加密存储实现
 *
 * 存储布局（NVS namespace "kv"，分区 "vault" + "vault2" 双区冗余）：
 *   "init"    : uint8 = 1          是否已初始化
 *   "salt"    : blob  32B          PBKDF2 盐
 *   "verif"   : blob  39B          AES-GCM(已知明文) 验证 blob
 *   "cnt"     : int32              凭证数量
 *   "c0","c1"... : blob            AES-256-GCM(nonce|tag|ciphertext|crc32)
 *   "kcnt"    : int32              KV 条目数量
 *   "k0","k1"... : blob            KV 条目: key(32B) + AES-256-GCM(nonce|tag|ciphertext|crc32)
 *
 * 完整性：每个 blob 末尾附加 CRC32，读取时校验
 * 冗余：写入同时写 vault + vault2，读取时双区校验，自动修复
 */

#include "keyvault.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "esp_crc.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "json_util.h"

#include "mbedtls/pkcs5.h"
#include "mbedtls/gcm.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#define TAG "KeyVault"

#define NVS_PART1 "vault"
#define NVS_PART2 "vault2"
#define NVS_NS    "kv"

#define GCM_NONCE_LEN 12
#define GCM_TAG_LEN   12  /* 12字节标签（NIST推荐） */
#define CRC_LEN       4   /* CRC32 长度 */

/* blob 最小长度: nonce + tag + crc（即使 ciphertext 为空） */
#define BLOB_MIN_LEN  (GCM_NONCE_LEN + GCM_TAG_LEN + CRC_LEN)

/* 存储格式版本：
 * v1: 原版 JSON
 * v2: 带 CRC 盐
 * v3: 512KB 分区 + 1536 条容量 + 独创 7-bit 字符压缩 + 双区自愈监控 */
#define VAULT_FORMAT_VERSION 3u

/* ── 内部状态 ── */
static bool     s_setup      = false;
static bool     s_unlocked   = false;
static uint8_t  s_aes_key[32];
static char     s_session_token[VAULT_SESSION_TOKEN_LEN];
static int64_t  s_last_activity_us = 0;
static mbedtls_ctr_drbg_context s_ctr_drbg;
static mbedtls_entropy_context  s_entropy;

/* ── 质量与健康监控 ── */
static uint32_t s_total_writes = 0;
static uint32_t s_heal_count   = 0;
static bool     s_read_only_safe_mode = false;

/* ── 口令爆破防护 ──
 * PBKDF2 30k 轮，连续失败阶梯式冷却，成功后清零。 */
static uint32_t s_fail_count = 0;
static int64_t  s_retry_after_us = 0;

/* ── 条数缓存 ── */
static int32_t  s_cred_cnt = 0;
static int32_t  s_kv_cnt   = 0;
static bool     s_cnt_valid = false;

/* ── NVS 双句柄 ── */
static nvs_handle_t s_nvs1 = 0;
static nvs_handle_t s_nvs2 = 0;

/* ── 并发保护 ──
 * 全局只有一份 s_nvs1/s_nvs2、s_aes_key、会话状态，而调用方不止一个任务：
 *   HTTP 任务（所有 Web API）、LED 任务（轮询 vault_is_unlocked）。
 * 后者的 check_auto_lock() 可能在 HTTP 任务正在用 s_aes_key 解密时把密钥清零，
 * 属于实打实的竞态。这里用互斥锁把所有公开 API 串起来。
 * 说明：esp_http_server 本身是单任务顺序执行 handler，加锁不会带来额外阻塞。
 * 加了锁的是"会话/密钥/设置"状态；CRUD 与 KV 接口依赖"只在 HTTP 任务调用"这一约定
 * （它们共享 s_nvs1/s_nvs2 两个全局句柄），若将来引入第二个调用方需一并纳入锁保护。 */
static SemaphoreHandle_t s_mutex = NULL;

#define VAULT_LOCK()    do { if (s_mutex) xSemaphoreTake(s_mutex, portMAX_DELAY); } while (0)
#define VAULT_UNLOCK()  do { if (s_mutex) xSemaphoreGive(s_mutex); } while (0)

/* 内部版本：由持锁者调用，避免公开入口重复加锁 */
static void vault_lock_locked(void);

/* ── 内部辅助 ── */

void vault_secure_zero(void *p, size_t n)
{
    volatile uint8_t *vp = (volatile uint8_t *)p;
    while (n--) *vp++ = 0;
}
#define secure_zero vault_secure_zero

static esp_err_t generate_random_bytes(uint8_t *buf, size_t len)
{
    int ret = mbedtls_ctr_drbg_random(&s_ctr_drbg, buf, len);
    if (ret != 0) {
        ESP_LOGE(TAG, "RNG 取数失败: -0x%04X", -ret);
        return ESP_FAIL;
    }
    return ESP_OK;
}

/* 拒绝采样：消除 r % pool_len 的模偏置（pool_len 一般不是 256 的约数） */
static esp_err_t random_below(uint8_t bound, uint8_t *out)
{
    if (bound == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    /* 只接受 [0, limit) 区间内的随机字节，保证每个取值概率相同 */
    uint16_t limit = 256 - (256 % bound);
    uint8_t r;
    uint16_t guard = 0;
    do {
        if (generate_random_bytes(&r, 1) != ESP_OK) {
            return ESP_FAIL;
        }
        if (++guard > 512) {                 /* 理论上几乎不可能触发，防止异常时死循环 */
            return ESP_FAIL;
        }
    } while ((uint16_t)r >= limit);
    *out = (uint8_t)(r % bound);
    return ESP_OK;
}

static esp_err_t derive_key_with_iter(const char *password, const uint8_t *salt, size_t salt_len,
                                      uint32_t iterations, uint8_t *key_out)
{
    int64_t t0 = esp_timer_get_time();
    int ret = mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256,
                                             (const uint8_t *)password, strlen(password),
                                             salt, salt_len,
                                             iterations,
                                             32, key_out);
    ESP_LOGI(TAG, "PBKDF2 %u 轮耗时 %lld ms", (unsigned)iterations,
             (long long)((esp_timer_get_time() - t0) / 1000));
    return ret == 0 ? ESP_OK : ESP_FAIL;
}

static esp_err_t derive_key(const char *password, const uint8_t *salt, size_t salt_len,
                             uint8_t *key_out)
{
    return derive_key_with_iter(password, salt, salt_len, VAULT_PBKDF2_ITERATIONS, key_out);
}

static esp_err_t aes_gcm_encrypt(const uint8_t *key,
                                  const uint8_t *plaintext, size_t plain_len,
                                  uint8_t *out_nonce, uint8_t *out_tag, uint8_t *out_cipher)
{
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (ret != 0) { mbedtls_gcm_free(&gcm); return ESP_FAIL; }
    if (generate_random_bytes(out_nonce, GCM_NONCE_LEN) != ESP_OK) {
        mbedtls_gcm_free(&gcm);
        return ESP_FAIL;
    }
    ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plain_len,
                                     out_nonce, GCM_NONCE_LEN,
                                     NULL, 0, plaintext, out_cipher,
                                     GCM_TAG_LEN, out_tag);
    mbedtls_gcm_free(&gcm);
    return ret == 0 ? ESP_OK : ESP_FAIL;
}

static esp_err_t aes_gcm_decrypt(const uint8_t *key,
                                  const uint8_t *nonce, const uint8_t *tag,
                                  const uint8_t *ciphertext, size_t cipher_len,
                                  uint8_t *out_plain)
{
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (ret != 0) { mbedtls_gcm_free(&gcm); return ESP_FAIL; }
    ret = mbedtls_gcm_auth_decrypt(&gcm, cipher_len,
                                    nonce, GCM_NONCE_LEN,
                                    NULL, 0, tag, GCM_TAG_LEN,
                                    ciphertext, out_plain);
    mbedtls_gcm_free(&gcm);
    return ret == 0 ? ESP_OK : ESP_FAIL;
}

/* ── CRC32 辅助 ── */

/* 给 blob 尾部追加 CRC32（blob 已含 nonce+tag+ciphertext） */
static void blob_append_crc(uint8_t *blob, size_t data_len)
{
    uint32_t crc = esp_crc32_le(0, blob, data_len);
    memcpy(blob + data_len, &crc, CRC_LEN);
}

/* 校验 blob 尾部 CRC32，返回 true = 完整 */
static bool blob_verify_crc(const uint8_t *blob, size_t total_len)
{
    if (total_len < BLOB_MIN_LEN) return false;
    size_t data_len = total_len - CRC_LEN;
    uint32_t expected = esp_crc32_le(0, blob, data_len);
    uint32_t stored;
    memcpy(&stored, blob + data_len, CRC_LEN);
    return expected == stored;
}

/* ── NVS 双区操作 ── */

static esp_err_t nvs_open_both(void)
{
    esp_err_t err1 = ESP_OK, err2 = ESP_OK;
    if (s_nvs1 == 0) err1 = nvs_open_from_partition(NVS_PART1, NVS_NS, NVS_READWRITE, &s_nvs1);
    if (s_nvs2 == 0) err2 = nvs_open_from_partition(NVS_PART2, NVS_NS, NVS_READWRITE, &s_nvs2);
    /* 至少一个分区可用即可 */
    if (err1 != ESP_OK && err2 != ESP_OK) return err1;
    return ESP_OK;
}

static void nvs_close_both(void)
{
    if (s_nvs1 != 0) { nvs_close(s_nvs1); s_nvs1 = 0; }
    if (s_nvs2 != 0) { nvs_close(s_nvs2); s_nvs2 = 0; }
}

/* 写入两个分区：任一分片成功即视为成功，两片都失败（最常见是分区写满）才报错。
 * 注意：绝不能无条件吞掉错误——否则空间耗尽时"添加成功"是假象，重启后数据消失。 */
static esp_err_t dual_set_blob(const char *key, const void *blob, size_t len)
{
    esp_err_t err1 = ESP_OK, err2 = ESP_OK;
    bool tried = false;
    if (s_nvs1 != 0) { err1 = nvs_set_blob(s_nvs1, key, blob, len); tried = true; }
    if (s_nvs2 != 0) { err2 = nvs_set_blob(s_nvs2, key, blob, len); tried = true; }
    if (!tried) return ESP_ERR_INVALID_STATE;
    s_total_writes++;
    if (err1 == ESP_OK && err2 == ESP_OK) return ESP_OK;
    if (err1 == ESP_OK || err2 == ESP_OK) {
        /* 单区成功：数据保住了，但冗余已失效，必须让用户能在日志里看到 */
        ESP_LOGW(TAG, "'%s' 仅写入单个分区，冗余已失效: %d / %d", key, err1, err2);
        return ESP_OK;
    }
    ESP_LOGE(TAG, "'%s' 双区写入均失败: %d / %d，进入安全只读降级保护模式", key, err1, err2);
    s_read_only_safe_mode = true;
    return err1;
}

static esp_err_t dual_set_u8(const char *key, uint8_t val)
{
    s_total_writes++;
    if (s_nvs1 != 0) nvs_set_u8(s_nvs1, key, val);
    if (s_nvs2 != 0) nvs_set_u8(s_nvs2, key, val);
    return ESP_OK;
}

static esp_err_t dual_set_i32(const char *key, int32_t val)
{
    s_total_writes++;
    if (s_nvs1 != 0) nvs_set_i32(s_nvs1, key, val);
    if (s_nvs2 != 0) nvs_set_i32(s_nvs2, key, val);
    return ESP_OK;
}

static esp_err_t dual_set_u32(const char *key, uint32_t val)
{
    s_total_writes++;
    if (s_nvs1 != 0) nvs_set_u32(s_nvs1, key, val);
    if (s_nvs2 != 0) nvs_set_u32(s_nvs2, key, val);
    return ESP_OK;
}

static esp_err_t dual_get_u32(const char *key, uint32_t *out)
{
    if (s_nvs1 != 0 && nvs_get_u32(s_nvs1, key, out) == ESP_OK) return ESP_OK;
    if (s_nvs2 != 0 && nvs_get_u32(s_nvs2, key, out) == ESP_OK) return ESP_OK;
    return ESP_ERR_NVS_NOT_FOUND;
}

static esp_err_t dual_commit(void)
{
    esp_err_t err1 = ESP_OK, err2 = ESP_OK;
    bool tried = false;
    if (s_nvs1 != 0) { err1 = nvs_commit(s_nvs1); tried = true; }
    if (s_nvs2 != 0) { err2 = nvs_commit(s_nvs2); tried = true; }
    if (!tried) return ESP_ERR_INVALID_STATE;
    if (err1 == ESP_OK || err2 == ESP_OK) return ESP_OK;
    ESP_LOGE(TAG, "双区提交均失败: %d / %d，进入安全只读保护", err1, err2);
    s_read_only_safe_mode = true;
    return err1;
}

/* 从双区读取 blob，优先 CRC 校验通过的那个。
 * out_cap 为调用方缓冲区容量：防止 NVS 里出现超长 blob 时写越界。
 * 成功时 *len_out 为去掉 CRC32 后的数据长度。 */
static esp_err_t dual_get_blob(const char *key, void *out, size_t *len_out, size_t out_cap)
{
    uint8_t buf1[1024], buf2[1024];
    size_t len1 = sizeof(buf1), len2 = sizeof(buf2);
    bool ok1 = false, ok2 = false;
    bool found1 = false, found2 = false;

    if (s_nvs1 != 0 && nvs_get_blob(s_nvs1, key, buf1, &len1) == ESP_OK) {
        found1 = true;
        ok1 = blob_verify_crc(buf1, len1);
    }
    if (s_nvs2 != 0 && nvs_get_blob(s_nvs2, key, buf2, &len2) == ESP_OK) {
        found2 = true;
        ok2 = blob_verify_crc(buf2, len2);
    }

    if (ok1 && (len1 - CRC_LEN) > out_cap) {
        ESP_LOGE(TAG, "'%s' blob 长度 %u 超出缓冲区 %u", key,
                 (unsigned)(len1 - CRC_LEN), (unsigned)out_cap);
        return ESP_ERR_INVALID_SIZE;
    }
    if (ok2 && (len2 - CRC_LEN) > out_cap) {
        ESP_LOGE(TAG, "'%s' blob 长度 %u 超出缓冲区 %u", key,
                 (unsigned)(len2 - CRC_LEN), (unsigned)out_cap);
        return ESP_ERR_INVALID_SIZE;
    }

    if (ok1) {
        memcpy(out, buf1, len1 - CRC_LEN);
        *len_out = len1 - CRC_LEN; /* 返回不含 CRC 的数据长度 */
        /* 如果区2损坏，自愈修复它 */
        if (!ok2 && s_nvs2 != 0) {
            ESP_LOGW(TAG, "vault2 '%s' 损坏，从 vault1 交叉自愈修复", key);
            s_heal_count++;
            nvs_set_blob(s_nvs2, key, buf1, len1);
            nvs_commit(s_nvs2);
        }
        return ESP_OK;
    }
    if (ok2) {
        memcpy(out, buf2, len2 - CRC_LEN);
        *len_out = len2 - CRC_LEN;
        /* 如果区1损坏，自愈修复它 */
        if (s_nvs1 != 0) {
            ESP_LOGW(TAG, "vault1 '%s' 损坏，从 vault2 交叉自愈修复", key);
            s_heal_count++;
            nvs_set_blob(s_nvs1, key, buf2, len2);
            nvs_commit(s_nvs1);
        }
        return ESP_OK;
    }

    /* 只有真正读到过内容但 CRC 均不过，才算"双区损坏"；
     * 两个分区都没有这个 key 时应返回 NOT_FOUND（旧实现恒返回 INVALID_STATE，
     * 因为 len1/len2 初值是缓冲区容量而不是实际长度）。 */
    if (found1 || found2) {
        ESP_LOGE(TAG, "'%s' 双区均损坏", key);
        return ESP_ERR_INVALID_STATE;
    }
    return ESP_ERR_NVS_NOT_FOUND;
}

/* 从双区读取 u8 */
static esp_err_t dual_get_u8(const char *key, uint8_t *out)
{
    if (s_nvs1 != 0 && nvs_get_u8(s_nvs1, key, out) == ESP_OK) return ESP_OK;
    if (s_nvs2 != 0 && nvs_get_u8(s_nvs2, key, out) == ESP_OK) return ESP_OK;
    return ESP_ERR_NVS_NOT_FOUND;
}

/* 从双区读取 i32 */
static esp_err_t dual_get_i32(const char *key, int32_t *out)
{
    if (s_nvs1 != 0 && nvs_get_i32(s_nvs1, key, out) == ESP_OK) return ESP_OK;
    if (s_nvs2 != 0 && nvs_get_i32(s_nvs2, key, out) == ESP_OK) return ESP_OK;
    return ESP_ERR_NVS_NOT_FOUND;
}

/* ── 条数缓存 ── */

static void cnt_invalidate(void)
{
    s_cnt_valid = false;
    s_cred_cnt = 0;
    s_kv_cnt = 0;
}

/* 惰性装载条数：解锁期间只在首次访问（或失效后）读一次 NVS。
 * 若调用方已经打开了句柄，装载后不能顺手关掉，否则会把调用方脚下的句柄抽走。 */
static void cnt_ensure_loaded(void)
{
    if (s_cnt_valid) {
        return;
    }
    bool was_open = (s_nvs1 != 0 || s_nvs2 != 0);
    if (nvs_open_both() != ESP_OK) {
        return;
    }
    int32_t c = 0, k = 0;
    dual_get_i32("cnt", &c);
    dual_get_i32("kcnt", &k);
    if (!was_open) {
        nvs_close_both();
    }
    s_cred_cnt = (c < 0) ? 0 : (c > VAULT_MAX_ENTRIES ? VAULT_MAX_ENTRIES : c);
    s_kv_cnt = (k < 0) ? 0 : (k > VAULT_MAX_KV_ENTRIES ? VAULT_MAX_KV_ENTRIES : k);
    s_cnt_valid = true;
}

/* ── 凭证序列化 ── */

/* 落盘格式仍然是 JSON，但必须逐字段转义：
 * 密码里出现 " 或 \ 时，旧实现直接 snprintf 拼接会产出非法 JSON，
 * 再次读取时解析失败 → 该条凭证永久读不出来（静默数据丢失）。 */
static esp_err_t cred_to_json(const vault_cred_t *c, char *out, size_t out_len)
{
    size_t o = 0;
#define JSON_PUT(lit) do { \
        const char *s_ = (lit); size_t n_ = strlen(s_); \
        if (o + n_ + 1 > out_len) return ESP_ERR_INVALID_SIZE; \
        memcpy(out + o, s_, n_); o += n_; \
    } while (0)
#define JSON_PUT_FIELD(val) do { \
        JSON_PUT("\""); \
        size_t w_ = json_escape_str(out + o, out_len - o, (val)); \
        o += w_; \
        if (o + 2 > out_len) return ESP_ERR_INVALID_SIZE; \
        out[o++] = '"'; out[o] = '\0'; \
    } while (0)

    JSON_PUT("{\"name\":");
    JSON_PUT_FIELD(c->name);
    JSON_PUT(",\"url\":");
    JSON_PUT_FIELD(c->url);
    JSON_PUT(",\"user\":");
    JSON_PUT_FIELD(c->username);
    JSON_PUT(",\"pass\":");
    JSON_PUT_FIELD(c->password);
    JSON_PUT("}");
#undef JSON_PUT_FIELD
#undef JSON_PUT
    out[o] = '\0';
    return ESP_OK;
}

static bool json_to_cred(const char *json, vault_cred_t *c)
{
    memset(c, 0, sizeof(*c));
    return json_get_str_field(json, "name", c->name, VAULT_MAX_NAME_LEN)
        && json_get_str_field(json, "url",  c->url,  VAULT_MAX_URL_LEN)
        && json_get_str_field(json, "user", c->username, VAULT_MAX_USER_LEN)
        && json_get_str_field(json, "pass", c->password, VAULT_MAX_PASS_LEN);
}

/* ── 确定性两级压缩（TLV 二进制布局 + 7-bit 字符位打包） ── */

/* 检查字符串是否全由 7-bit ASCII 字符组成 (0x00 .. 0x7F) */
static bool is_ascii_7bit(const char *s, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if ((uint8_t)s[i] > 0x7F) return false;
    }
    return true;
}

/* 7-bit 位打包：将 in_len 个 7-bit 字符打包为 ceil(in_len * 7 / 8) 字节
 * 返回打包后的字节数 */
static size_t pack_7bit(const uint8_t *in, size_t in_len, uint8_t *out)
{
    size_t out_len = (in_len * 7 + 7) / 8;
    memset(out, 0, out_len);
    size_t bit_pos = 0;
    for (size_t i = 0; i < in_len; i++) {
        uint8_t val = in[i] & 0x7F;
        size_t byte_idx = bit_pos / 8;
        size_t bit_offset = bit_pos % 8;
        out[byte_idx] |= (val << bit_offset);
        if (bit_offset > 1) {
            out[byte_idx + 1] |= (val >> (8 - bit_offset));
        }
        bit_pos += 7;
    }
    return out_len;
}

/* 7-bit 解包：从输入字节流还原 raw_len 个 7-bit 字符 */
static void unpack_7bit(const uint8_t *in, size_t raw_len, uint8_t *out)
{
    size_t bit_pos = 0;
    for (size_t i = 0; i < raw_len; i++) {
        size_t byte_idx = bit_pos / 8;
        size_t bit_offset = bit_pos % 8;
        uint8_t val = (in[byte_idx] >> bit_offset) & 0x7F;
        if (bit_offset > 1) {
            val |= (in[byte_idx + 1] << (8 - bit_offset)) & 0x7F;
        }
        out[i] = val;
        bit_pos += 7;
    }
}

#define VAULT_TLV_MAGIC 0x56 /* 'V' */

/* 序列化凭证为紧凑 TLV + 7-bit 位打包格式 */
static esp_err_t cred_to_packed(const vault_cred_t *c, uint8_t *out, size_t out_max, size_t *out_len)
{
    out[0] = VAULT_TLV_MAGIC;
    size_t offset = 1;

    const char *fields[4] = { c->name, c->url, c->username, c->password };
    for (uint8_t tag = 1; tag <= 4; tag++) {
        const char *f = fields[tag - 1];
        size_t slen = strlen(f);
        bool use_7bit = (slen > 0) && is_ascii_7bit(f, slen);
        size_t dlen = use_7bit ? ((slen * 7 + 7) / 8) : slen;

        if (offset + 6 + dlen > out_max) return ESP_ERR_INVALID_SIZE;

        out[offset++] = tag;
        out[offset++] = use_7bit ? 1 : 0;
        out[offset++] = (uint8_t)(slen & 0xFF);
        out[offset++] = (uint8_t)((slen >> 8) & 0xFF);
        out[offset++] = (uint8_t)(dlen & 0xFF);
        out[offset++] = (uint8_t)((dlen >> 8) & 0xFF);

        if (use_7bit) {
            pack_7bit((const uint8_t *)f, slen, out + offset);
        } else if (slen > 0) {
            memcpy(out + offset, f, slen);
        }
        offset += dlen;
    }
    *out_len = offset;
    return ESP_OK;
}

/* 反序列化凭证（支持 V3 紧凑格式与旧版 JSON 格式回退） */
static bool packed_to_cred(const uint8_t *in, size_t in_len, vault_cred_t *c)
{
    if (in_len < 1) return false;
    if (in[0] == '{') {
        /* 旧版 JSON 兼容回退 */
        return json_to_cred((const char *)in, c);
    }
    if (in[0] != VAULT_TLV_MAGIC) return false;

    memset(c, 0, sizeof(*c));
    size_t offset = 1;
    while (offset + 6 <= in_len) {
        uint8_t tag = in[offset++];
        uint8_t is_7bit = in[offset++];
        uint16_t rlen = in[offset] | ((uint16_t)in[offset + 1] << 8); offset += 2;
        uint16_t dlen = in[offset] | ((uint16_t)in[offset + 1] << 8); offset += 2;

        if (offset + dlen > in_len) return false;

        char *dst = NULL;
        size_t max_dst = 0;
        switch (tag) {
            case 1: dst = c->name;     max_dst = VAULT_MAX_NAME_LEN; break;
            case 2: dst = c->url;      max_dst = VAULT_MAX_URL_LEN; break;
            case 3: dst = c->username; max_dst = VAULT_MAX_USER_LEN; break;
            case 4: dst = c->password; max_dst = VAULT_MAX_PASS_LEN; break;
            default: break;
        }

        if (dst && max_dst > 0) {
            if (rlen >= max_dst) rlen = max_dst - 1;
            if (is_7bit) {
                unpack_7bit(in + offset, rlen, (uint8_t *)dst);
                dst[rlen] = '\0';
            } else {
                size_t copy_n = (dlen < max_dst - 1) ? dlen : (max_dst - 1);
                memcpy(dst, in + offset, copy_n);
                dst[copy_n] = '\0';
            }
        }
        offset += dlen;
    }
    return true;
}

/* 序列化 KV 值（若纯 ASCII 则启用 7-bit 压缩） */
static esp_err_t kv_to_packed(const char *val, uint8_t *out, size_t out_max, size_t *out_len)
{
    size_t slen = strlen(val);
    bool use_7bit = (slen > 0) && is_ascii_7bit(val, slen);
    size_t dlen = use_7bit ? ((slen * 7 + 7) / 8) : slen;

    if (3 + dlen > out_max) return ESP_ERR_INVALID_SIZE;
    out[0] = use_7bit ? 0x01 : 0x00;
    out[1] = (uint8_t)(slen & 0xFF);
    out[2] = (uint8_t)((slen >> 8) & 0xFF);
    if (use_7bit) {
        pack_7bit((const uint8_t *)val, slen, out + 3);
    } else {
        memcpy(out + 3, val, slen);
    }
    *out_len = 3 + dlen;
    return ESP_OK;
}

/* 反序列化 KV 值（支持 7-bit、未压缩 UTF-8 与旧版裸文本兼容） */
static esp_err_t packed_to_kv(const uint8_t *in, size_t in_len, char *out, size_t max_out)
{
    if (in_len == 0) {
        if (max_out > 0) out[0] = '\0';
        return ESP_OK;
    }
    /* 旧版兼容：首字节为普通 ASCII 可打印字符 (>= 0x20) */
    if (in[0] >= 0x20) {
        size_t cpy = in_len < max_out - 1 ? in_len : max_out - 1;
        memcpy(out, in, cpy);
        out[cpy] = '\0';
        return ESP_OK;
    }
    uint8_t flag = in[0];
    if (in_len < 3) return ESP_ERR_INVALID_SIZE;
    uint16_t rlen = in[1] | ((uint16_t)in[2] << 8);
    const uint8_t *data = in + 3;
    size_t dlen = in_len - 3;

    if (flag == 0x01) {
        size_t actual_out = rlen < max_out - 1 ? rlen : max_out - 1;
        unpack_7bit(data, actual_out, (uint8_t *)out);
        out[actual_out] = '\0';
    } else {
        size_t cpy = dlen < max_out - 1 ? dlen : max_out - 1;
        memcpy(out, data, cpy);
        out[cpy] = '\0';
    }
    return ESP_OK;
}

/* ── 会话与锁定 ── */

static esp_err_t generate_session_token(char *out, size_t len)
{
    uint8_t rand_bytes[16];
    if (generate_random_bytes(rand_bytes, sizeof(rand_bytes)) != ESP_OK) {
        out[0] = '\0';
        return ESP_FAIL;
    }
    size_t i;
    for (i = 0; i < 16 && i * 2 + 1 < len; i++) {
        snprintf(out + i * 2, 3, "%02x", rand_bytes[i]);
    }
    out[i * 2] = '\0';
    secure_zero(rand_bytes, sizeof(rand_bytes));
    return ESP_OK;
}

/* 恒定时间比较：避免 strcmp 提前返回造成的令牌逐字节爆破侧信道。
 * 调用前已确认两者长度相同，这里按固定长度全量比较。 */
static bool token_equal_const_time(const char *a, const char *b)
{
    unsigned diff = 0;
    for (size_t i = 0; i < VAULT_SESSION_TOKEN_LEN; i++) {
        diff |= (unsigned)(unsigned char)a[i] ^ (unsigned)(unsigned char)b[i];
    }
    return diff == 0;
}

/* 会话超时检查：必须在持锁状态下调用（内部版本，公开入口负责加锁） */
static void check_auto_lock_locked(void)
{
    if (!s_unlocked) return;
    int64_t now = esp_timer_get_time();
    if ((now - s_last_activity_us) > (int64_t)VAULT_LOCK_TIMEOUT_MS * 1000) {
        ESP_LOGI(TAG, "会话超时，自动锁定");
        vault_lock_locked();
    }
}

/* ── 公共 API ── */

esp_err_t vault_init(void)
{
    /* 初始化两个 NVS 分区 */
    esp_err_t ret1 = nvs_flash_init_partition(NVS_PART1);
    if (ret1 == ESP_ERR_NVS_NO_FREE_PAGES || ret1 == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase_partition(NVS_PART1);
        ret1 = nvs_flash_init_partition(NVS_PART1);
    }
    esp_err_t ret2 = nvs_flash_init_partition(NVS_PART2);
    if (ret2 == ESP_ERR_NVS_NO_FREE_PAGES || ret2 == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase_partition(NVS_PART2);
        ret2 = nvs_flash_init_partition(NVS_PART2);
    }
    if (ret1 != ESP_OK && ret2 != ESP_OK) {
        ESP_LOGE(TAG, "双区 NVS 初始化均失败: %d / %d", ret1, ret2);
        return ESP_FAIL;
    }

    /* 随机数生成器 */
    mbedtls_entropy_init(&s_entropy);
    mbedtls_ctr_drbg_init(&s_ctr_drbg);
    int ret = mbedtls_ctr_drbg_seed(&s_ctr_drbg, mbedtls_entropy_func, &s_entropy,
                                     (const uint8_t *)"KeyVault", 8);
    if (ret != 0) {
        ESP_LOGE(TAG, "RNG 初始化失败: %d", ret);
        return ESP_FAIL;
    }

    if (s_mutex == NULL) {
        s_mutex = xSemaphoreCreateMutex();
        if (s_mutex == NULL) {
            ESP_LOGE(TAG, "互斥锁创建失败");
            return ESP_FAIL;
        }
    }

    /* 检查是否已设置主密码 */
    esp_err_t err = nvs_open_both();
    if (err != ESP_OK) return err;

    /* 存储格式版本校验：分区扩容或布局变更后，旧数据对本固件不可用，
     * 直接重建双区，避免留下"读得出来但解不开"的库。 */
    uint32_t fmt = 0;
    bool fmt_ok = (dual_get_u32("fmt", &fmt) == ESP_OK && fmt == VAULT_FORMAT_VERSION);
    if (!fmt_ok) {
        ESP_LOGW(TAG, "vault 存储格式不匹配（读到 %u，期望 %u），重建双区", (unsigned)fmt,
                 (unsigned)VAULT_FORMAT_VERSION);
        if (s_nvs1 != 0) { nvs_erase_all(s_nvs1); nvs_commit(s_nvs1); }
        if (s_nvs2 != 0) { nvs_erase_all(s_nvs2); nvs_commit(s_nvs2); }
        dual_set_u32("fmt", VAULT_FORMAT_VERSION);
        dual_commit();
        s_setup = false;
    } else {
        uint8_t init_flag = 0;
        dual_get_u8("init", &init_flag);
        s_setup = (init_flag == 1);
    }
    nvs_close_both();

    ESP_LOGI(TAG, "Vault 初始化完成 (双区，格式 v%u)，已设置: %s",
             (unsigned)VAULT_FORMAT_VERSION, s_setup ? "是" : "否");
    return ESP_OK;
}

bool vault_is_setup(void)
{
    VAULT_LOCK();
    bool v = s_setup;
    VAULT_UNLOCK();
    return v;
}

/* 验证 blob: AES-256-GCM 加密已知明文 */
static const char VERIFY_PLAINTEXT[] = "KeyVault Verify";
#define VERIFY_BLOB_LEN (GCM_NONCE_LEN + GCM_TAG_LEN + sizeof(VERIFY_PLAINTEXT) - 1 + CRC_LEN)

/* salt 落盘同样带 CRC32：
 * 旧实现写入 32B 裸 salt，却走"带 CRC 校验"的读取路径，校验必然失败，
 * vault_unlock() 永远取不到 salt —— 表现为重启后输入正确主密码也提示错误。 */
#define SALT_LEN        32
#define SALT_BLOB_LEN   (SALT_LEN + CRC_LEN)

esp_err_t vault_setup(const char *master_password, char *token_out, size_t token_len)
{
    VAULT_LOCK();

    if (s_setup) { VAULT_UNLOCK(); return ESP_ERR_INVALID_STATE; }
    if (!master_password || strlen(master_password) < 4) { VAULT_UNLOCK(); return ESP_ERR_INVALID_ARG; }

    esp_err_t err = nvs_open_both();
    if (err != ESP_OK) { VAULT_UNLOCK(); return err; }

    uint8_t salt_blob[SALT_BLOB_LEN];
    err = generate_random_bytes(salt_blob, SALT_LEN);
    if (err != ESP_OK) goto fail;
    blob_append_crc(salt_blob, SALT_LEN);

    err = derive_key(master_password, salt_blob, SALT_LEN, s_aes_key);
    if (err != ESP_OK) goto fail;

    /* 验证 blob: nonce(12) + tag(12) + ciphertext(15) + crc32(4) */
    uint8_t verify_blob[VERIFY_BLOB_LEN];
    err = aes_gcm_encrypt(s_aes_key,
                           (const uint8_t *)VERIFY_PLAINTEXT,
                           sizeof(VERIFY_PLAINTEXT) - 1,
                           verify_blob,
                           verify_blob + GCM_NONCE_LEN,
                           verify_blob + GCM_NONCE_LEN + GCM_TAG_LEN);
    if (err != ESP_OK) goto fail;
    blob_append_crc(verify_blob, VERIFY_BLOB_LEN - CRC_LEN);

    /* 双区写入：任一步失败都要上报，不能"假装创建成功" */
    err = dual_set_blob("salt", salt_blob, SALT_BLOB_LEN);
    if (err != ESP_OK) goto fail;
    err = dual_set_blob("verif", verify_blob, VERIFY_BLOB_LEN);
    if (err != ESP_OK) goto fail;
    dual_set_u8("init", 1);
    dual_set_u32("fmt", VAULT_FORMAT_VERSION);
    dual_set_u32("iter", VAULT_PBKDF2_ITERATIONS);
    dual_set_i32("cnt", 0);
    dual_set_i32("kcnt", 0);
    err = dual_commit();
    if (err != ESP_OK) goto fail;

    /* 成功后直接保持解锁：调用方不必再跑一遍 PBKDF2 */
    s_setup = true;
    s_unlocked = true;
    s_fail_count = 0;
    s_retry_after_us = 0;
    s_last_activity_us = esp_timer_get_time();
    s_cred_cnt = 0;
    s_kv_cnt = 0;
    s_cnt_valid = true;
    err = generate_session_token(s_session_token, VAULT_SESSION_TOKEN_LEN);
    if (err != ESP_OK) goto fail;
    if (token_out) strlcpy(token_out, s_session_token, token_len);
    ESP_LOGI(TAG, "主密码设置成功");

    secure_zero(salt_blob, sizeof(salt_blob));
    nvs_close_both();
    VAULT_UNLOCK();
    return ESP_OK;

fail:
    /* 回滚可能已经写进去的 init 标记，避免留下"已设置但无法解锁"的半成品库 */
    if (s_nvs1 != 0) { nvs_erase_key(s_nvs1, "init"); nvs_commit(s_nvs1); }
    if (s_nvs2 != 0) { nvs_erase_key(s_nvs2, "init"); nvs_commit(s_nvs2); }
    secure_zero(s_aes_key, 32);
    secure_zero(salt_blob, sizeof(salt_blob));
    s_unlocked = false;
    s_setup = false;
    cnt_invalidate();
    nvs_close_both();
    VAULT_UNLOCK();
    return (err != ESP_OK) ? err : ESP_FAIL;
}

esp_err_t vault_unlock(const char *master_password, char *token_out, size_t token_len)
{
    VAULT_LOCK();

    if (!s_setup) { VAULT_UNLOCK(); return ESP_ERR_INVALID_STATE; }
    if (!master_password) { VAULT_UNLOCK(); return ESP_ERR_INVALID_ARG; }

    check_auto_lock_locked();
    if (s_unlocked && token_out) {
        strlcpy(token_out, s_session_token, token_len);
        VAULT_UNLOCK();
        return ESP_OK;
    }

    /* 连续失败冷却（对"密码错误"返回同一个错误码，不泄露是否处于冷却） */
    int64_t now = esp_timer_get_time();
    if (now < s_retry_after_us) {
        ESP_LOGW(TAG, "口令尝试过于频繁，%.1f 秒后再试",
                 (double)(s_retry_after_us - now) / 1000000.0);
        VAULT_UNLOCK();
        return ESP_ERR_INVALID_STATE;
    }

    esp_err_t err = nvs_open_both();
    if (err != ESP_OK) { VAULT_UNLOCK(); return err; }

    /* 读取盐和验证 blob（双区校验） */
    uint8_t salt[SALT_LEN];
    uint8_t verify_blob_raw[VERIFY_BLOB_LEN];
    size_t salt_len = 0, vblob_len = 0;

    err = dual_get_blob("salt", salt, &salt_len, sizeof(salt));
    if (err != ESP_OK) goto done;
    if (salt_len != SALT_LEN) { err = ESP_ERR_INVALID_SIZE; goto done; }

    err = dual_get_blob("verif", verify_blob_raw, &vblob_len, sizeof(verify_blob_raw));
    if (err != ESP_OK) goto done;
    if (vblob_len < GCM_NONCE_LEN + GCM_TAG_LEN + 1) { err = ESP_ERR_INVALID_SIZE; goto done; }

    /* 读取迭代次数（存量旧库可能没有保存该字段） */
    uint32_t iter = 0;
    bool has_iter = (dual_get_u32("iter", &iter) == ESP_OK && iter > 0);
    if (!has_iter) {
        iter = VAULT_PBKDF2_ITERATIONS; /* 优先尝试 30000 轮 */
    }

    uint8_t key[32];
    err = derive_key_with_iter(master_password, salt, SALT_LEN, iter, key);
    if (err != ESP_OK) {
        secure_zero(salt, sizeof(salt));
        goto done;
    }

    /* 解密验证 blob */
    const uint8_t *nonce = verify_blob_raw;
    const uint8_t *tag = verify_blob_raw + GCM_NONCE_LEN;
    const uint8_t *cipher = verify_blob_raw + GCM_NONCE_LEN + GCM_TAG_LEN;
    size_t cipher_len = vblob_len - GCM_NONCE_LEN - GCM_TAG_LEN;

    uint8_t decrypted[sizeof(VERIFY_PLAINTEXT)];
    err = aes_gcm_decrypt(key, nonce, tag, cipher, cipher_len, decrypted);
    bool pass_ok = (err == ESP_OK && memcmp(decrypted, VERIFY_PLAINTEXT, sizeof(VERIFY_PLAINTEXT) - 1) == 0);

    /* 兼容性回退：若当前尝试失败且先前没有存储 iter，尝试旧版 600k 轮 */
    if (!pass_ok && !has_iter) {
        ESP_LOGI(TAG, "首选 30k 轮未匹配，尝试旧版 600k 轮 PBKDF2 回退校验...");
        err = derive_key_with_iter(master_password, salt, SALT_LEN, VAULT_PBKDF2_LEGACY_ITERATIONS, key);
        if (err == ESP_OK) {
            err = aes_gcm_decrypt(key, nonce, tag, cipher, cipher_len, decrypted);
            if (err == ESP_OK && memcmp(decrypted, VERIFY_PLAINTEXT, sizeof(VERIFY_PLAINTEXT) - 1) == 0) {
                pass_ok = true;
                dual_set_u32("iter", VAULT_PBKDF2_LEGACY_ITERATIONS);
                dual_commit();
                ESP_LOGI(TAG, "识别为旧版 600k 轮密库，验证成功已记录标记");
            }
        }
    }
    secure_zero(salt, sizeof(salt));

    if (!pass_ok) {
        ESP_LOGW(TAG, "主密码错误");
        secure_zero(key, 32);
        secure_zero(decrypted, sizeof(decrypted));
        s_fail_count++;
        uint32_t cool_s = (s_fail_count <= 2) ? 1 : ((s_fail_count <= 5) ? 3 : 10);
        s_retry_after_us = esp_timer_get_time() + (int64_t)cool_s * 1000000;
        err = ESP_ERR_INVALID_STATE;
        goto done;
    }
    secure_zero(decrypted, sizeof(decrypted));

    memcpy(s_aes_key, key, 32);
    secure_zero(key, 32);
    s_unlocked = true;
    s_fail_count = 0;
    s_retry_after_us = 0;
    s_last_activity_us = esp_timer_get_time();
    cnt_invalidate();                  /* 换密钥后重新装载条数 */
    err = generate_session_token(s_session_token, VAULT_SESSION_TOKEN_LEN);
    if (err != ESP_OK) { s_unlocked = false; secure_zero(s_aes_key, 32); goto done; }
    if (token_out) strlcpy(token_out, s_session_token, token_len);
    ESP_LOGI(TAG, "Vault 已解锁");

done:
    nvs_close_both();
    VAULT_UNLOCK();
    return err;
}

bool vault_is_unlocked(void)
{
    VAULT_LOCK();
    check_auto_lock_locked();
    bool u = s_unlocked;
    VAULT_UNLOCK();
    return u;
}

void vault_lock(void)
{
    VAULT_LOCK();
    vault_lock_locked();
    VAULT_UNLOCK();
}

static void vault_lock_locked(void)
{
    secure_zero(s_aes_key, 32);
    s_unlocked = false;
    s_session_token[0] = '\0';
    cnt_invalidate();
    ESP_LOGI(TAG, "Vault 已锁定");
}

bool vault_validate_token(const char *token)
{
    VAULT_LOCK();
    check_auto_lock_locked();
    bool ok = false;
    if (s_unlocked && token) {
        /* 先比长度再按定长做恒定时间比较 */
        if (strlen(token) == VAULT_SESSION_TOKEN_LEN - 1 &&
            token_equal_const_time(token, s_session_token)) {
            ok = true;
            s_last_activity_us = esp_timer_get_time();
        }
    }
    VAULT_UNLOCK();
    return ok;
}

/* ── 凭证 CRUD（带 CRC + 双区）── */

int vault_cred_count(void)
{
    if (!s_unlocked) return 0;
    cnt_ensure_loaded();
    return (int)s_cred_cnt;
}

esp_err_t vault_get_cred(int index, vault_cred_t *out)
{
    if (!s_unlocked || !out) return ESP_ERR_INVALID_STATE;
    int cnt = vault_cred_count();
    if (index < 0 || index >= cnt) return ESP_ERR_NOT_FOUND;

    esp_err_t err = nvs_open_both();
    if (err != ESP_OK) return err;

    char nvs_key[16];
    snprintf(nvs_key, sizeof(nvs_key), "c%d", index);

    uint8_t raw[1024];
    size_t data_len = 0;
    err = dual_get_blob(nvs_key, raw, &data_len, sizeof(raw));
    if (err != ESP_OK) goto done;
    if (data_len < GCM_NONCE_LEN + GCM_TAG_LEN) { err = ESP_ERR_INVALID_SIZE; goto done; }

    /* 解析: nonce(12) + tag(12) + ciphertext */
    size_t cipher_len = data_len - GCM_NONCE_LEN - GCM_TAG_LEN;
    uint8_t *plain = malloc(cipher_len + 1);
    if (!plain) { err = ESP_ERR_NO_MEM; goto done; }

    err = aes_gcm_decrypt(s_aes_key,
                           raw, raw + GCM_NONCE_LEN,
                           raw + GCM_NONCE_LEN + GCM_TAG_LEN,
                           cipher_len, plain);
    if (err != ESP_OK) { free(plain); goto done; }

    plain[cipher_len] = '\0';
    bool ok = packed_to_cred(plain, cipher_len, out);
    secure_zero(plain, cipher_len + 1);
    free(plain);
    err = ok ? ESP_OK : ESP_FAIL;

done:
    nvs_close_both();
    return err;
}

/* 内部：构建加密 blob（含 CRC） */
static esp_err_t build_encrypted_blob_with_key(const uint8_t *key, const uint8_t *plain,
                                                size_t plain_len,
                                                uint8_t **out_blob, size_t *out_len)
{
    size_t blob_len = GCM_NONCE_LEN + GCM_TAG_LEN + plain_len + CRC_LEN;
    uint8_t *blob = malloc(blob_len);
    if (!blob) return ESP_ERR_NO_MEM;

    esp_err_t err = aes_gcm_encrypt(key, plain, plain_len,
                                     blob,                                /* nonce */
                                     blob + GCM_NONCE_LEN,               /* tag */
                                     blob + GCM_NONCE_LEN + GCM_TAG_LEN); /* cipher */
    if (err != ESP_OK) { free(blob); return err; }
    blob_append_crc(blob, blob_len - CRC_LEN);
    *out_blob = blob;
    *out_len = blob_len;
    return ESP_OK;
}

static esp_err_t build_encrypted_blob(const uint8_t *plain, size_t plain_len,
                                       uint8_t **out_blob, size_t *out_len)
{
    return build_encrypted_blob_with_key(s_aes_key, plain, plain_len, out_blob, out_len);
}

/* 序列化缓冲区要按"最坏情况全部转义"来开：每个字符最多膨胀到 6 字节(\u00XX)，
 * 常见情况（引号/反斜杠/换行）是 2 字节，所以按 2 倍 + 固定开销取值。 */
#define CRED_JSON_BUF_LEN \
    (2 * (VAULT_MAX_NAME_LEN + VAULT_MAX_URL_LEN + VAULT_MAX_USER_LEN + VAULT_MAX_PASS_LEN) + 64)

esp_err_t vault_add_cred(const vault_cred_t *cred)
{
    if (!s_unlocked || !cred) return ESP_ERR_INVALID_STATE;
    if (s_read_only_safe_mode) return ESP_ERR_NOT_ALLOWED;

    int32_t cnt = vault_cred_count();
    if (cnt >= VAULT_MAX_ENTRIES) return ESP_ERR_NO_MEM;

    esp_err_t err = nvs_open_both();
    if (err != ESP_OK) return err;

    uint8_t packed[sizeof(vault_cred_t) + 32];
    size_t packed_len = 0;
    err = cred_to_packed(cred, packed, sizeof(packed), &packed_len);
    if (err != ESP_OK) goto done;

    uint8_t *blob = NULL;
    size_t blob_len = 0;
    err = build_encrypted_blob(packed, packed_len, &blob, &blob_len);
    secure_zero(packed, sizeof(packed));
    if (err != ESP_OK) goto done;

    char nvs_key[16];
    snprintf(nvs_key, sizeof(nvs_key), "c%d", (int)cnt);
    err = dual_set_blob(nvs_key, blob, blob_len);
    secure_zero(blob, blob_len);
    free(blob);
    if (err != ESP_OK) goto done;

    cnt++;
    dual_set_i32("cnt", cnt);
    err = dual_commit();
    if (err != ESP_OK) goto done;

    s_cred_cnt = cnt;                  /* 只有真正落盘成功才推进缓存 */
    ESP_LOGI(TAG, "添加凭证 #%d: %s", (int)cnt - 1, cred->name);

done:
    nvs_close_both();
    return err;
}

esp_err_t vault_update_cred(int index, const vault_cred_t *cred)
{
    if (!s_unlocked || !cred) return ESP_ERR_INVALID_STATE;
    if (s_read_only_safe_mode) return ESP_ERR_NOT_ALLOWED;
    int cnt = vault_cred_count();
    if (index < 0 || index >= cnt) return ESP_ERR_NOT_FOUND;

    esp_err_t err = nvs_open_both();
    if (err != ESP_OK) return err;

    uint8_t packed[sizeof(vault_cred_t) + 32];
    size_t packed_len = 0;
    err = cred_to_packed(cred, packed, sizeof(packed), &packed_len);
    if (err != ESP_OK) goto done;

    uint8_t *blob = NULL;
    size_t blob_len = 0;
    err = build_encrypted_blob(packed, packed_len, &blob, &blob_len);
    secure_zero(packed, sizeof(packed));
    if (err != ESP_OK) goto done;

    char nvs_key[16];
    snprintf(nvs_key, sizeof(nvs_key), "c%d", index);
    err = dual_set_blob(nvs_key, blob, blob_len);
    secure_zero(blob, blob_len);
    free(blob);
    if (err != ESP_OK) goto done;

    err = dual_commit();
    if (err != ESP_OK) goto done;
    ESP_LOGI(TAG, "更新凭证 #%d: %s", index, cred->name);

done:
    nvs_close_both();
    return err;
}

esp_err_t vault_delete_cred(int index)
{
    if (!s_unlocked) return ESP_ERR_INVALID_STATE;
    if (s_read_only_safe_mode) return ESP_ERR_NOT_ALLOWED;
    int cnt = vault_cred_count();
    if (index < 0 || index >= cnt) return ESP_ERR_NOT_FOUND;

    esp_err_t err = nvs_open_both();
    if (err != ESP_OK) return err;

    for (int i = index; i < cnt - 1; i++) {
        char k_src[16], k_dst[16];
        snprintf(k_src, sizeof(k_src), "c%d", i + 1);
        snprintf(k_dst, sizeof(k_dst), "c%d", i);
        uint8_t buf[1024];
        size_t len = 0;
        if (dual_get_blob(k_src, buf, &len, sizeof(buf)) == ESP_OK) {
            /* 重新追加 CRC（因为 dual_get_blob 去掉了 CRC） */
            size_t full_len = len + CRC_LEN;
            blob_append_crc(buf, len);
            err = dual_set_blob(k_dst, buf, full_len);
            if (err != ESP_OK) goto done;
        }
    }

    char nvs_key[16];
    snprintf(nvs_key, sizeof(nvs_key), "c%d", (int)(cnt - 1));
    if (s_nvs1 != 0) nvs_erase_key(s_nvs1, nvs_key);
    if (s_nvs2 != 0) nvs_erase_key(s_nvs2, nvs_key);

    cnt--;
    dual_set_i32("cnt", cnt);
    err = dual_commit();
    if (err != ESP_OK) goto done;

    s_cred_cnt = cnt;
    ESP_LOGI(TAG, "删除凭证 #%d，剩余 %d", index, (int)cnt);

done:
    nvs_close_both();
    return err;
}

/* ── 任意字符串 KV 存储 ── */

int vault_kv_count(void)
{
    if (!s_unlocked) return 0;
    cnt_ensure_loaded();
    return (int)s_kv_cnt;
}

/* KV blob 格式: key(32B) + nonce(12) + tag(12) + ciphertext + crc32(4) */
#define KV_HEADER_LEN VAULT_MAX_KV_KEY_LEN

esp_err_t vault_kv_set(const char *key, const char *value)
{
    if (!s_unlocked || !key || !value) return ESP_ERR_INVALID_STATE;
    if (s_read_only_safe_mode) return ESP_ERR_NOT_ALLOWED;
    if (strlen(key) >= VAULT_MAX_KV_KEY_LEN) return ESP_ERR_INVALID_ARG;
    if (strlen(value) >= VAULT_MAX_KV_VAL_LEN) return ESP_ERR_INVALID_ARG;

    esp_err_t err = nvs_open_both();
    if (err != ESP_OK) return err;

    /* 先检查 key 是否已存在 */
    int32_t cnt = vault_kv_count();
    int exist_idx = -1;
    size_t key_len = strlen(key);
    for (int i = 0; i < cnt; i++) {
        char nvs_key[16];
        snprintf(nvs_key, sizeof(nvs_key), "k%d", i);
        uint8_t raw[1024];
        size_t data_len = 0;
        if (dual_get_blob(nvs_key, raw, &data_len, sizeof(raw)) == ESP_OK &&
            data_len >= KV_HEADER_LEN) {
            /* 连结尾 NUL 一起比较，避免出现"前缀命中"误判 */
            if (memcmp(raw, key, key_len + 1) == 0) {
                exist_idx = i;
                break;
            }
        }
    }

    /* 压缩打包 value */
    uint8_t packed_val[VAULT_MAX_KV_VAL_LEN + 16];
    size_t packed_val_len = 0;
    err = kv_to_packed(value, packed_val, sizeof(packed_val), &packed_val_len);
    if (err != ESP_OK) goto done;

    /* 构建 blob: key(32B) + encrypted value */
    size_t enc_data_len = GCM_NONCE_LEN + GCM_TAG_LEN + packed_val_len;
    size_t blob_len = KV_HEADER_LEN + enc_data_len + CRC_LEN;
    uint8_t *blob = malloc(blob_len);
    if (!blob) { secure_zero(packed_val, sizeof(packed_val)); err = ESP_ERR_NO_MEM; goto done; }

    /* 填充 key（固定32B，不足补零） */
    memset(blob, 0, KV_HEADER_LEN);
    memcpy(blob, key, strlen(key));

    /* 加密 packed_val */
    err = aes_gcm_encrypt(s_aes_key, packed_val, packed_val_len,
                           blob + KV_HEADER_LEN,                          /* nonce */
                           blob + KV_HEADER_LEN + GCM_NONCE_LEN,          /* tag */
                           blob + KV_HEADER_LEN + GCM_NONCE_LEN + GCM_TAG_LEN);
    secure_zero(packed_val, sizeof(packed_val));
    if (err != ESP_OK) { free(blob); goto done; }
    blob_append_crc(blob, blob_len - CRC_LEN);

    char nvs_key[16];
    if (exist_idx >= 0) {
        snprintf(nvs_key, sizeof(nvs_key), "k%d", exist_idx);
    } else {
        if (cnt >= VAULT_MAX_KV_ENTRIES) { free(blob); err = ESP_ERR_NO_MEM; goto done; }
        snprintf(nvs_key, sizeof(nvs_key), "k%d", (int)cnt);
    }
    err = dual_set_blob(nvs_key, blob, blob_len);
    secure_zero(blob, blob_len);
    free(blob);
    if (err != ESP_OK) goto done;

    if (exist_idx < 0) {
        cnt++;
        dual_set_i32("kcnt", cnt);
    }
    err = dual_commit();
    if (err != ESP_OK) goto done;

    s_kv_cnt = cnt;
    ESP_LOGI(TAG, "KV set '%s'", key);

done:
    nvs_close_both();
    return err;
}

esp_err_t vault_kv_get(const char *key, char *value_out, size_t max_len)
{
    if (!s_unlocked || !key || !value_out || max_len == 0) return ESP_ERR_INVALID_STATE;

    esp_err_t err = nvs_open_both();
    if (err != ESP_OK) return err;

    int32_t cnt = vault_kv_count();
    size_t key_len = strlen(key);

    for (int i = 0; i < cnt; i++) {
        char nvs_key[16];
        snprintf(nvs_key, sizeof(nvs_key), "k%d", i);
        uint8_t raw[1024];
        size_t data_len = 0;
        if (dual_get_blob(nvs_key, raw, &data_len, sizeof(raw)) != ESP_OK) continue;
        if (data_len < KV_HEADER_LEN + GCM_NONCE_LEN + GCM_TAG_LEN) continue;

        /* 检查 key 匹配 */
        if (memcmp(raw, key, key_len + 1) != 0) continue;

        /* 解密 value */
        size_t cipher_len = data_len - KV_HEADER_LEN - GCM_NONCE_LEN - GCM_TAG_LEN;
        uint8_t *plain = malloc(cipher_len + 1);
        if (!plain) { err = ESP_ERR_NO_MEM; goto done; }

        uint8_t *enc = raw + KV_HEADER_LEN;
        err = aes_gcm_decrypt(s_aes_key,
                               enc, enc + GCM_NONCE_LEN,
                               enc + GCM_NONCE_LEN + GCM_TAG_LEN,
                               cipher_len, plain);
        if (err != ESP_OK) { free(plain); goto done; }

        plain[cipher_len] = '\0';
        err = packed_to_kv(plain, cipher_len, value_out, max_len);
        secure_zero(plain, cipher_len + 1);
        free(plain);
        goto done;
    }
    err = ESP_ERR_NVS_NOT_FOUND;

done:
    nvs_close_both();
    return err;
}

esp_err_t vault_kv_delete(const char *key)
{
    if (!s_unlocked || !key) return ESP_ERR_INVALID_STATE;
    if (s_read_only_safe_mode) return ESP_ERR_NOT_ALLOWED;

    esp_err_t err = nvs_open_both();
    if (err != ESP_OK) return err;

    int32_t cnt = vault_kv_count();
    size_t key_len = strlen(key);

    int del_idx = -1;
    for (int i = 0; i < cnt; i++) {
        char nvs_key[16];
        snprintf(nvs_key, sizeof(nvs_key), "k%d", i);
        uint8_t raw[1024];
        size_t data_len = 0;
        if (dual_get_blob(nvs_key, raw, &data_len, sizeof(raw)) == ESP_OK &&
            data_len >= KV_HEADER_LEN) {
            if (memcmp(raw, key, key_len + 1) == 0) {
                del_idx = i;
                break;
            }
        }
    }

    if (del_idx < 0) { err = ESP_ERR_NVS_NOT_FOUND; goto done; }

    /* 后续条目前移 */
    for (int i = del_idx; i < cnt - 1; i++) {
        char k_src[16], k_dst[16];
        snprintf(k_src, sizeof(k_src), "k%d", i + 1);
        snprintf(k_dst, sizeof(k_dst), "k%d", i);
        uint8_t buf[1024];
        size_t len = 0;
        if (dual_get_blob(k_src, buf, &len, sizeof(buf)) == ESP_OK) {
            size_t full_len = len + CRC_LEN;
            blob_append_crc(buf, len);
            err = dual_set_blob(k_dst, buf, full_len);
            if (err != ESP_OK) goto done;
        }
    }

    char nvs_key[16];
    snprintf(nvs_key, sizeof(nvs_key), "k%d", (int)(cnt - 1));
    if (s_nvs1 != 0) nvs_erase_key(s_nvs1, nvs_key);
    if (s_nvs2 != 0) nvs_erase_key(s_nvs2, nvs_key);

    cnt--;
    dual_set_i32("kcnt", cnt);
    err = dual_commit();
    if (err != ESP_OK) goto done;

    s_kv_cnt = cnt;
    ESP_LOGI(TAG, "KV delete '%s'", key);

done:
    nvs_close_both();
    return err;
}

esp_err_t vault_kv_list(char keys_out[][VAULT_MAX_KV_KEY_LEN], int max_keys, int *count_out)
{
    if (!s_unlocked || !keys_out || !count_out) return ESP_ERR_INVALID_STATE;

    esp_err_t err = nvs_open_both();
    if (err != ESP_OK) return err;

    int32_t cnt = vault_kv_count();
    *count_out = 0;

    int listed = 0;
    for (int i = 0; i < cnt && listed < max_keys; i++) {
        char nvs_key[16];
        snprintf(nvs_key, sizeof(nvs_key), "k%d", i);
        uint8_t raw[1024];
        size_t data_len = 0;
        if (dual_get_blob(nvs_key, raw, &data_len, sizeof(raw)) == ESP_OK && data_len >= KV_HEADER_LEN) {
            /* 提取 key 名（最多 VAULT_MAX_KV_KEY_LEN-1 字符） */
            memset(keys_out[listed], 0, VAULT_MAX_KV_KEY_LEN);
            size_t klen = strnlen((char *)raw, KV_HEADER_LEN);
            if (klen >= VAULT_MAX_KV_KEY_LEN) klen = VAULT_MAX_KV_KEY_LEN - 1;
            memcpy(keys_out[listed], raw, klen);
            keys_out[listed][klen] = '\0';
            listed++;
        }
    }
    *count_out = listed;
    nvs_close_both();
    return ESP_OK;
}

/* ── 密码生成 ── */

esp_err_t vault_generate_password(char *out, size_t len,
                                   bool upper, bool lower,
                                   bool digits, bool symbols)
{
    if (!out || len < 2) return ESP_ERR_INVALID_ARG;
    const char *UPPER   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const char *LOWER   = "abcdefghijklmnopqrstuvwxyz";
    const char *DIGITS  = "0123456789";
    const char *SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>?";
    char pool[128] = {0};
    if (upper)   strlcat(pool, UPPER, sizeof(pool));
    if (lower)   strlcat(pool, LOWER, sizeof(pool));
    if (digits)  strlcat(pool, DIGITS, sizeof(pool));
    if (symbols) strlcat(pool, SYMBOLS, sizeof(pool));
    if (strlen(pool) == 0) strlcat(pool, LOWER, sizeof(pool));
    size_t pool_len = strlen(pool);
    if (pool_len > 255) {
        return ESP_ERR_INVALID_ARG;
    }
    for (size_t i = 0; i < len - 1; i++) {
        uint8_t r;
        /* 拒绝采样取代 r % pool_len：后者对非 2 的幂字符集存在模偏置 */
        if (random_below((uint8_t)pool_len, &r) != ESP_OK) {
            secure_zero(out, len);
            return ESP_FAIL;
        }
        out[i] = pool[r];
    }
    out[len - 1] = '\0';
    return ESP_OK;
}

/* ── 修改主密码 ── */

/* 用指定密钥把内存中的一批条目整体写回 NVS（调用方需已打开句柄）。
 * 修改主密码与失败回滚都复用这一段。 */
static esp_err_t rewrite_entries(const uint8_t *key,
                                 const vault_cred_t *creds, int cred_n,
                                 char (*kv_keys)[VAULT_MAX_KV_KEY_LEN],
                                 char (*kv_vals)[VAULT_MAX_KV_VAL_LEN], int kv_n)
{
    esp_err_t err = ESP_OK;

    for (int i = 0; i < cred_n; i++) {
        uint8_t packed[sizeof(vault_cred_t) + 32];
        size_t packed_len = 0;
        err = cred_to_packed(&creds[i], packed, sizeof(packed), &packed_len);
        if (err != ESP_OK) break;
        uint8_t *blob = NULL;
        size_t blob_len = 0;
        err = build_encrypted_blob_with_key(key, packed, packed_len,
                                            &blob, &blob_len);
        secure_zero(packed, sizeof(packed));
        if (err != ESP_OK) break;
        char nvs_key[16];
        snprintf(nvs_key, sizeof(nvs_key), "c%d", i);
        err = dual_set_blob(nvs_key, blob, blob_len);
        secure_zero(blob, blob_len);
        free(blob);
        if (err != ESP_OK) break;
    }
    if (err != ESP_OK) {
        return err;
    }

    for (int i = 0; i < kv_n; i++) {
        uint8_t packed_val[VAULT_MAX_KV_VAL_LEN + 16];
        size_t packed_val_len = 0;
        err = kv_to_packed(kv_vals[i], packed_val, sizeof(packed_val), &packed_val_len);
        if (err != ESP_OK) break;
        size_t blob_len = KV_HEADER_LEN + GCM_NONCE_LEN + GCM_TAG_LEN + packed_val_len + CRC_LEN;
        uint8_t *blob = calloc(1, blob_len);
        if (!blob) { err = ESP_ERR_NO_MEM; break; }
        memcpy(blob, kv_keys[i], strnlen(kv_keys[i], KV_HEADER_LEN));
        err = aes_gcm_encrypt(key, packed_val, packed_val_len,
                              blob + KV_HEADER_LEN,
                              blob + KV_HEADER_LEN + GCM_NONCE_LEN,
                              blob + KV_HEADER_LEN + GCM_NONCE_LEN + GCM_TAG_LEN);
        secure_zero(packed_val, sizeof(packed_val));
        if (err != ESP_OK) { free(blob); return err; }
        blob_append_crc(blob, blob_len - CRC_LEN);
        char nvs_key[16];
        snprintf(nvs_key, sizeof(nvs_key), "k%d", i);
        err = dual_set_blob(nvs_key, blob, blob_len);
        secure_zero(blob, blob_len);
        free(blob);
        if (err != ESP_OK) return err;
    }
    return ESP_OK;
}

esp_err_t vault_change_password(const char *old_password, const char *new_password,
                                char *token_out, size_t token_len)
{
    esp_err_t err = ESP_OK;
    int cred_n = 0, kv_n = 0;
    vault_cred_t *creds = NULL;
    char (*kv_keys)[VAULT_MAX_KV_KEY_LEN] = NULL;
    char (*kv_vals)[VAULT_MAX_KV_VAL_LEN] = NULL;
    uint8_t old_key_backup[32];
    uint8_t old_salt_blob[SALT_BLOB_LEN];
    uint8_t new_key[32];
    uint8_t new_salt_blob[SALT_BLOB_LEN];

    if (!s_setup || !s_unlocked) return ESP_ERR_INVALID_STATE;
    if (s_read_only_safe_mode) return ESP_ERR_NOT_ALLOWED;
    if (!old_password || !new_password || strlen(new_password) < 4) return ESP_ERR_INVALID_ARG;

    VAULT_LOCK();

    /* ── 1. 校验旧主密码：直接与内存中的密钥比对，省一次 GCM 解密 ── */
    err = nvs_open_both();
    if (err != ESP_OK) goto cleanup;
    {
        uint8_t old_salt[SALT_LEN];
        uint8_t old_key[32];
        size_t salt_len = 0;
        err = dual_get_blob("salt", old_salt, &salt_len, sizeof(old_salt));
        if (err == ESP_OK && salt_len != SALT_LEN) err = ESP_ERR_INVALID_SIZE;
        uint32_t old_iter = 0;
        if (dual_get_u32("iter", &old_iter) != ESP_OK || old_iter == 0) {
            old_iter = VAULT_PBKDF2_ITERATIONS;
        }
        if (err == ESP_OK) err = derive_key_with_iter(old_password, old_salt, SALT_LEN, old_iter, old_key);
        bool ok = (err == ESP_OK) && (memcmp(old_key, s_aes_key, 32) == 0);
        if (!ok && old_iter != VAULT_PBKDF2_LEGACY_ITERATIONS) {
            err = derive_key_with_iter(old_password, old_salt, SALT_LEN, VAULT_PBKDF2_LEGACY_ITERATIONS, old_key);
            ok = (err == ESP_OK) && (memcmp(old_key, s_aes_key, 32) == 0);
        }
        if (ok) {
            memcpy(old_salt_blob, old_salt, SALT_LEN);
            blob_append_crc(old_salt_blob, SALT_LEN);   /* 回滚时要把 CRC 补回去 */
        }
        secure_zero(old_key, sizeof(old_key));
        secure_zero(old_salt, sizeof(old_salt));
        nvs_close_both();
        if (!ok) { err = ESP_ERR_INVALID_STATE; goto cleanup; }
    }
    memcpy(old_key_backup, s_aes_key, 32);

    /* ── 2. 全部明文读进内存（这一阶段不改动任何落盘数据）── */
    cred_n = vault_cred_count();
    kv_n = vault_kv_count();
    if (cred_n > 0) {
        creds = calloc((size_t)cred_n, sizeof(*creds));
        if (!creds) { err = ESP_ERR_NO_MEM; goto cleanup; }
        for (int i = 0; i < cred_n; i++) {
            err = vault_get_cred(i, &creds[i]);
            if (err != ESP_OK) goto cleanup;
        }
    }
    if (kv_n > 0) {
        kv_keys = calloc((size_t)kv_n, sizeof(*kv_keys));
        kv_vals = calloc((size_t)kv_n, sizeof(*kv_vals));
        if (!kv_keys || !kv_vals) { err = ESP_ERR_NO_MEM; goto cleanup; }
        int listed = 0;
        err = vault_kv_list(kv_keys, kv_n, &listed);
        if (err != ESP_OK) goto cleanup;
        kv_n = listed;
        for (int i = 0; i < kv_n; i++) {
            err = vault_kv_get(kv_keys[i], kv_vals[i], VAULT_MAX_KV_VAL_LEN);
            if (err != ESP_OK) goto cleanup;
        }
    }

    /* ── 3. 生成新盐 / 新密钥 ── */
    err = generate_random_bytes(new_salt_blob, SALT_LEN);
    if (err != ESP_OK) goto cleanup;
    blob_append_crc(new_salt_blob, SALT_LEN);
    err = derive_key(new_password, new_salt_blob, SALT_LEN, new_key);
    if (err != ESP_OK) goto cleanup;

    /* ── 4. 切换到新密钥并全量重写 ── */
    err = nvs_open_both();
    if (err != ESP_OK) goto cleanup;
    memcpy(s_aes_key, new_key, 32);
    err = rewrite_entries(new_key, creds, cred_n, kv_keys, kv_vals, kv_n);
    if (err == ESP_OK) {
        uint8_t verify_blob[VERIFY_BLOB_LEN];
        err = aes_gcm_encrypt(s_aes_key, (const uint8_t *)VERIFY_PLAINTEXT,
                              sizeof(VERIFY_PLAINTEXT) - 1,
                              verify_blob, verify_blob + GCM_NONCE_LEN,
                              verify_blob + GCM_NONCE_LEN + GCM_TAG_LEN);
        if (err == ESP_OK) {
            blob_append_crc(verify_blob, VERIFY_BLOB_LEN - CRC_LEN);
            err = dual_set_blob("salt", new_salt_blob, SALT_BLOB_LEN);
            if (err == ESP_OK) err = dual_set_blob("verif", verify_blob, VERIFY_BLOB_LEN);
            if (err == ESP_OK) {
                dual_set_u8("init", 1);
                dual_set_u32("fmt", VAULT_FORMAT_VERSION);
                dual_set_u32("iter", VAULT_PBKDF2_ITERATIONS);
                dual_set_i32("cnt", cred_n);
                dual_set_i32("kcnt", kv_n);
                err = dual_commit();
            }
        }
    }

    if (err != ESP_OK) {
        /* 回滚：明文仍在内存里，用旧密钥重写一遍并恢复旧 salt
         *（verif 只在成功后才写，此时仍是旧的，无需回滚） */
        ESP_LOGE(TAG, "修改主密码失败(%d)，回滚到旧密钥", err);
        memcpy(s_aes_key, old_key_backup, 32);
        esp_err_t rb = rewrite_entries(old_key_backup, creds, cred_n, kv_keys, kv_vals, kv_n);
        if (rb == ESP_OK) {
            rb = dual_set_blob("salt", old_salt_blob, SALT_BLOB_LEN);
        }
        if (rb == ESP_OK) {
            dual_set_i32("cnt", cred_n);
            dual_set_i32("kcnt", kv_n);
            rb = dual_commit();
        }
        if (rb != ESP_OK) {
            ESP_LOGE(TAG, "回滚失败(%d)，请用旧密码验证数据，必要时重置", rb);
        }
        goto cleanup;
    }

    /* ── 5. 成功：签发新令牌，旧令牌同时失效 ── */
    s_last_activity_us = esp_timer_get_time();
    s_cred_cnt = cred_n;
    s_kv_cnt = kv_n;
    s_cnt_valid = true;
    err = generate_session_token(s_session_token, VAULT_SESSION_TOKEN_LEN);
    if (err == ESP_OK && token_out) strlcpy(token_out, s_session_token, token_len);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "主密码已更新（重新加密 %d 条凭证 / %d 条 KV）", cred_n, kv_n);
    }

cleanup:
    if (creds) { secure_zero(creds, (size_t)cred_n * sizeof(*creds)); free(creds); }
    if (kv_keys) { secure_zero(kv_keys, (size_t)kv_n * sizeof(*kv_keys)); free(kv_keys); }
    if (kv_vals) { secure_zero(kv_vals, (size_t)kv_n * sizeof(*kv_vals)); free(kv_vals); }
    secure_zero(old_key_backup, sizeof(old_key_backup));
    secure_zero(old_salt_blob, sizeof(old_salt_blob));
    secure_zero(new_key, sizeof(new_key));
    secure_zero(new_salt_blob, sizeof(new_salt_blob));
    nvs_close_both();
    VAULT_UNLOCK();
    return err;
}

/* ── 备份 / 恢复 ── */

#define BACKUP_MAGIC     "KVBK"
#define BACKUP_VERSION   1u
#define BACKUP_HDR_LEN   (4 + 1 + 4)    /* magic + version + payload_len */
#define BACKUP_CRC_LEN   4

/* ESP32-S3 不允许非对齐 32 位访问，统一逐字节读写 */
static void put_u32_le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
    p[2] = (uint8_t)((v >> 16) & 0xff);
    p[3] = (uint8_t)((v >> 24) & 0xff);
}

static uint32_t get_u32_le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* 可增长的输出缓冲 */
typedef struct {
    uint8_t *p;
    size_t   len;
    size_t   cap;
} buf_t;

static esp_err_t buf_reserve(buf_t *b, size_t extra)
{
    if (b->len + extra <= b->cap) {
        return ESP_OK;
    }
    size_t need = b->len + extra;
    size_t cap = b->cap ? b->cap : 512;
    while (cap < need) {
        if (cap > (size_t)512 * 1024) {
            return ESP_ERR_NO_MEM;
        }
        cap *= 2;
    }
    uint8_t *np = realloc(b->p, cap);
    if (!np) {
        return ESP_ERR_NO_MEM;
    }
    b->p = np;
    b->cap = cap;
    return ESP_OK;
}

static esp_err_t buf_put(buf_t *b, const void *data, size_t n)
{
    esp_err_t err = buf_reserve(b, n);
    if (err != ESP_OK) {
        return err;
    }
    memcpy(b->p + b->len, data, n);
    b->len += n;
    return ESP_OK;
}

static esp_err_t buf_put_u32(buf_t *b, uint32_t v)
{
    uint8_t t[4];
    put_u32_le(t, v);
    return buf_put(b, t, sizeof(t));
}

/* 带边界检查的只读游标 */
typedef struct {
    const uint8_t *p;
    size_t         len;
    size_t         pos;
} cursor_t;

static bool cur_get_u32(cursor_t *c, uint32_t *out)
{
    if (c->pos + 4 > c->len) {
        return false;
    }
    *out = get_u32_le(c->p + c->pos);
    c->pos += 4;
    return true;
}

static bool cur_get_bytes(cursor_t *c, const uint8_t **out, size_t n)
{
    if (n > c->len - c->pos) {
        return false;
    }
    *out = c->p + c->pos;
    c->pos += n;
    return true;
}

esp_err_t vault_export(uint8_t **out_buf, size_t *out_len)
{
    if (!s_unlocked || !out_buf || !out_len) return ESP_ERR_INVALID_STATE;
    *out_buf = NULL;
    *out_len = 0;

    VAULT_LOCK();

    esp_err_t err = nvs_open_both();
    if (err != ESP_OK) {
        VAULT_UNLOCK();
        return err;
    }

    buf_t payload = {0};
    int cred_n = vault_cred_count();
    int kv_n = vault_kv_count();

    err = buf_put_u32(&payload, (uint32_t)cred_n);
    if (err == ESP_OK) err = buf_put_u32(&payload, (uint32_t)kv_n);

    /* salt 与 verif：dual_get_blob 去掉了尾部 CRC，这里补回去以还原仓库原始形态 */
    uint8_t salt_blob[SALT_BLOB_LEN];
    size_t salt_len = 0;
    if (err == ESP_OK) {
        err = dual_get_blob("salt", salt_blob, &salt_len, sizeof(salt_blob));
    }
    if (err == ESP_OK) {
        blob_append_crc(salt_blob, salt_len);
        salt_len += CRC_LEN;
        err = buf_put_u32(&payload, (uint32_t)salt_len);
        if (err == ESP_OK) err = buf_put(&payload, salt_blob, salt_len);
    }
    secure_zero(salt_blob, sizeof(salt_blob));

    uint8_t verif_blob[VERIFY_BLOB_LEN];
    size_t verif_len = 0;
    if (err == ESP_OK) {
        err = dual_get_blob("verif", verif_blob, &verif_len, sizeof(verif_blob));
    }
    if (err == ESP_OK) {
        blob_append_crc(verif_blob, verif_len);
        verif_len += CRC_LEN;
        err = buf_put_u32(&payload, (uint32_t)verif_len);
        if (err == ESP_OK) err = buf_put(&payload, verif_blob, verif_len);
    }

    uint8_t raw[1024];
    for (int i = 0; err == ESP_OK && i < cred_n; i++) {
        char nvs_key[16];
        snprintf(nvs_key, sizeof(nvs_key), "c%d", i);
        size_t n = 0;
        err = dual_get_blob(nvs_key, raw, &n, sizeof(raw));
        if (err != ESP_OK) break;
        blob_append_crc(raw, n);
        n += CRC_LEN;
        err = buf_put_u32(&payload, (uint32_t)n);
        if (err == ESP_OK) err = buf_put(&payload, raw, n);
    }
    secure_zero(raw, sizeof(raw));

    for (int i = 0; err == ESP_OK && i < kv_n; i++) {
        char nvs_key[16];
        snprintf(nvs_key, sizeof(nvs_key), "k%d", i);
        size_t n = 0;
        err = dual_get_blob(nvs_key, raw, &n, sizeof(raw));
        if (err != ESP_OK) break;
        blob_append_crc(raw, n);
        n += CRC_LEN;
        err = buf_put_u32(&payload, (uint32_t)n);
        if (err == ESP_OK) err = buf_put(&payload, raw, n);
    }
    secure_zero(raw, sizeof(raw));
    nvs_close_both();

    if (err != ESP_OK) {
        free(payload.p);
        VAULT_UNLOCK();
        return err;
    }

    size_t total = BACKUP_HDR_LEN + payload.len + BACKUP_CRC_LEN;
    uint8_t *out = malloc(total);
    if (!out) {
        free(payload.p);
        VAULT_UNLOCK();
        return ESP_ERR_NO_MEM;
    }
    memcpy(out, BACKUP_MAGIC, 4);
    out[4] = (uint8_t)BACKUP_VERSION;
    put_u32_le(out + 5, (uint32_t)payload.len);
    memcpy(out + BACKUP_HDR_LEN, payload.p, payload.len);
    put_u32_le(out + BACKUP_HDR_LEN + payload.len,
               esp_crc32_le(0, payload.p, payload.len));

    secure_zero(payload.p, payload.len);
    free(payload.p);

    *out_buf = out;
    *out_len = total;
    ESP_LOGI(TAG, "已导出备份：%u 条凭证 / %u 条 KV，共 %u 字节",
             (unsigned)cred_n, (unsigned)kv_n, (unsigned)total);
    VAULT_UNLOCK();
    return ESP_OK;
}

esp_err_t vault_import(const uint8_t *buf, size_t len, const char *master_password)
{
    if (!buf || !master_password) return ESP_ERR_INVALID_ARG;
    if (s_read_only_safe_mode) return ESP_ERR_NOT_ALLOWED;
    if (len < BACKUP_HDR_LEN + BACKUP_CRC_LEN) return ESP_ERR_INVALID_SIZE;
    if (memcmp(buf, BACKUP_MAGIC, 4) != 0) return ESP_ERR_INVALID_ARG;
    if (buf[4] != BACKUP_VERSION) return ESP_ERR_NOT_SUPPORTED;

    uint32_t plen = get_u32_le(buf + 5);
    if ((size_t)plen + BACKUP_HDR_LEN + BACKUP_CRC_LEN != len) return ESP_ERR_INVALID_SIZE;

    const uint8_t *payload = buf + BACKUP_HDR_LEN;
    if (get_u32_le(payload + plen) != esp_crc32_le(0, payload, plen)) {
        return ESP_ERR_INVALID_CRC;
    }

    cursor_t c = { .p = payload, .len = plen, .pos = 0 };
    uint32_t cred_n, kv_n, salt_len, verif_len;
    const uint8_t *salt_blob, *verif_blob;

    if (!cur_get_u32(&c, &cred_n) || !cur_get_u32(&c, &kv_n)) return ESP_ERR_INVALID_SIZE;
    if (cred_n > VAULT_MAX_ENTRIES || kv_n > VAULT_MAX_KV_ENTRIES) return ESP_ERR_INVALID_SIZE;
    if (!cur_get_u32(&c, &salt_len) || salt_len != SALT_BLOB_LEN) return ESP_ERR_INVALID_SIZE;
    if (!cur_get_bytes(&c, &salt_blob, salt_len)) return ESP_ERR_INVALID_SIZE;
    if (!cur_get_u32(&c, &verif_len) || verif_len != VERIFY_BLOB_LEN) return ESP_ERR_INVALID_SIZE;
    if (!cur_get_bytes(&c, &verif_blob, verif_len)) return ESP_ERR_INVALID_SIZE;

    /* 先用备份里的 salt 校验主密码：通过后才有资格整库覆盖 */
    uint8_t key[32];
    esp_err_t err = derive_key(master_password, salt_blob, SALT_LEN, key);
    uint8_t deciphered[sizeof(VERIFY_PLAINTEXT)] = {0};
    bool ok = false;
    if (err == ESP_OK) {
        err = aes_gcm_decrypt(key, verif_blob,
                              verif_blob + GCM_NONCE_LEN,
                              verif_blob + GCM_NONCE_LEN + GCM_TAG_LEN,
                              verif_len - GCM_NONCE_LEN - GCM_TAG_LEN - CRC_LEN,
                              deciphered);
        ok = (err == ESP_OK) &&
             (memcmp(deciphered, VERIFY_PLAINTEXT, sizeof(VERIFY_PLAINTEXT) - 1) == 0);
    }
    secure_zero(deciphered, sizeof(deciphered));
    secure_zero(key, sizeof(key));
    if (!ok) {
        ESP_LOGW(TAG, "备份导入失败：主密码与备份不匹配");
        return ESP_ERR_INVALID_STATE;
    }

    VAULT_LOCK();

    err = nvs_open_both();
    if (err != ESP_OK) {
        VAULT_UNLOCK();
        return err;
    }
    if (s_nvs1 != 0) { nvs_erase_all(s_nvs1); nvs_commit(s_nvs1); }
    if (s_nvs2 != 0) { nvs_erase_all(s_nvs2); nvs_commit(s_nvs2); }

    err = dual_set_blob("salt", salt_blob, salt_len);
    if (err == ESP_OK) err = dual_set_blob("verif", verif_blob, verif_len);

    for (uint32_t i = 0; err == ESP_OK && i < cred_n; i++) {
        uint32_t blen;
        const uint8_t *blob;
        if (!cur_get_u32(&c, &blen) || !cur_get_bytes(&c, &blob, blen)) {
            err = ESP_ERR_INVALID_SIZE;
            break;
        }
        char nvs_key[16];
        snprintf(nvs_key, sizeof(nvs_key), "c%u", (unsigned)i);
        err = dual_set_blob(nvs_key, blob, blen);
    }
    for (uint32_t i = 0; err == ESP_OK && i < kv_n; i++) {
        uint32_t blen;
        const uint8_t *blob;
        if (!cur_get_u32(&c, &blen) || !cur_get_bytes(&c, &blob, blen)) {
            err = ESP_ERR_INVALID_SIZE;
            break;
        }
        char nvs_key[16];
        snprintf(nvs_key, sizeof(nvs_key), "k%u", (unsigned)i);
        err = dual_set_blob(nvs_key, blob, blen);
    }
    if (err == ESP_OK) {
        dual_set_u8("init", 1);
        dual_set_u32("fmt", VAULT_FORMAT_VERSION);
        dual_set_i32("cnt", (int32_t)cred_n);
        dual_set_i32("kcnt", (int32_t)kv_n);
        err = dual_commit();
    }
    nvs_close_both();

    if (err == ESP_OK) {
        s_setup = true;
        /* 强制回到锁定态：内存中的密钥与新导入的数据无关，必须重新解锁 */
        vault_lock_locked();
        ESP_LOGW(TAG, "已从备份恢复 %u 条凭证 / %u 条 KV，请用主密码重新解锁",
                 (unsigned)cred_n, (unsigned)kv_n);
    }
    VAULT_UNLOCK();
    return err;
}

/* ── 重置（双区都清）── */

esp_err_t vault_reset(void)
{
    VAULT_LOCK();

    esp_err_t err = nvs_open_both();
    if (err != ESP_OK) { VAULT_UNLOCK(); return err; }
    if (s_nvs1 != 0) { nvs_erase_all(s_nvs1); nvs_commit(s_nvs1); }
    if (s_nvs2 != 0) { nvs_erase_all(s_nvs2); nvs_commit(s_nvs2); }
    /* 重新写入格式标记，避免下次启动被判定为"格式不匹配"再来一次全擦 */
    dual_set_u32("fmt", VAULT_FORMAT_VERSION);
    dual_commit();
    nvs_close_both();
    vault_lock_locked();
    s_setup = false;
    s_fail_count = 0;
    s_retry_after_us = 0;
    cnt_invalidate();
    ESP_LOGW(TAG, "Vault 已重置（双区已清除）");
    VAULT_UNLOCK();
    return ESP_OK;
}

/* ── 健康监控与只读模式 ── */

esp_err_t vault_get_health_stats(vault_health_stats_t *out)
{
    if (!out) return ESP_ERR_INVALID_ARG;
    VAULT_LOCK();
    out->total_writes = s_total_writes;
    out->heal_count = s_heal_count;
    out->cred_count = s_cred_cnt;
    out->kv_count = s_kv_cnt;
    out->max_creds = VAULT_MAX_ENTRIES;
    out->max_kvs = VAULT_MAX_KV_ENTRIES;
    out->read_only_safe_mode = s_read_only_safe_mode;

    nvs_stats_t nvs_stats;
    if (nvs_get_stats(NVS_PART1, &nvs_stats) == ESP_OK) {
        out->free_entries = nvs_stats.free_entries;
        out->used_entries = nvs_stats.used_entries;
    } else {
        out->free_entries = 0;
        out->used_entries = 0;
    }
    VAULT_UNLOCK();
    return ESP_OK;
}

bool vault_is_read_only(void)
{
    return s_read_only_safe_mode;
}



