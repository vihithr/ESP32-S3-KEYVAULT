/*
 * keyvault —— ESP32 密钥管理工具 · 加密存储模块
 *
 * 安全设计：
 *   - 主密码 → PBKDF2-HMAC-SHA256 (600,000轮, OWASP 2023) → AES-256 密钥
 *   - 验证方式: AES-GCM 加密已知明文，解密成功=密码正确（无离线验证攻击面）
 *   - 每条凭证用独立 nonce 的 AES-256-GCM 加密
 *   - 双区冗余: vault + vault2 两个 NVS 分区互为备份
 *   - CRC32 校验: 每个 blob 末尾附加 CRC32，读取时校验完整性
 *   - 会话令牌 + 5分钟无操作自动锁定；USB 拔出立即锁定
 *   - 口令连续失败阶梯冷却（1s / 3s / 10s）
 */
#pragma once

#include "esp_err.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VAULT_MAX_ENTRIES      1024      /* 账号凭证上限 1024 条 */
#define VAULT_MAX_NAME_LEN     64
#define VAULT_MAX_URL_LEN      128
#define VAULT_MAX_USER_LEN     128
#define VAULT_MAX_PASS_LEN     256
#define VAULT_MAX_KV_KEY_LEN   32
#define VAULT_MAX_KV_VAL_LEN   512
#define VAULT_MAX_KV_ENTRIES   512       /* 自由存储上限 512 条，总计 1536 条 */
#define VAULT_SESSION_TOKEN_LEN 33  /* 32 hex chars + null */
#define VAULT_PBKDF2_ITERATIONS        30000     /* 嵌入式标准，240MHz ESP32-S3 下耗时约 0.9s */
#define VAULT_PBKDF2_LEGACY_ITERATIONS 600000    /* 旧版兼容，用于平滑过渡已存在的旧密库 */
#define VAULT_LOCK_TIMEOUT_MS          (15 * 60 * 1000) /* 15分钟自动锁定 */

typedef struct {
    char name[VAULT_MAX_NAME_LEN];
    char url[VAULT_MAX_URL_LEN];
    char username[VAULT_MAX_USER_LEN];
    char password[VAULT_MAX_PASS_LEN];
} vault_cred_t;

typedef struct {
    uint32_t total_writes;        /* 累计写入次数 */
    uint32_t heal_count;          /* 触发双区 CRC 校验自愈次数 */
    uint32_t cred_count;          /* 当前凭证条数 */
    uint32_t kv_count;            /* 当前 KV 条数 */
    uint32_t max_creds;           /* 最大凭证上限 (1024) */
    uint32_t max_kvs;             /* 最大 KV 上限 (512) */
    uint32_t free_entries;        /* NVS 空闲 Entry 插槽数 */
    uint32_t used_entries;        /* NVS 已用 Entry 插槽数 */
    bool read_only_safe_mode;     /* 是否处于安全只读降级保护模式 */
} vault_health_stats_t;

/* 获取存储健康状态 */
esp_err_t vault_get_health_stats(vault_health_stats_t *out);

/* 是否处于安全只读模式 */
bool vault_is_read_only(void);

/* 初始化 vault NVS 分区（含双区） */
esp_err_t vault_init(void);

/* 是否已完成主密码设置 */
bool vault_is_setup(void);

/* 首次设置主密码；成功后直接处于解锁态并回传会话令牌
 * （旧实现在 setup 末尾强制上锁，调用方只能再跑一遍 PBKDF2 才能拿到令牌，
 *   等于把 600k 轮派生做两遍，设置流程耗时翻倍） */
esp_err_t vault_setup(const char *master_password, char *token_out, size_t token_len);

/* 解锁 vault，成功返回会话令牌 */
esp_err_t vault_unlock(const char *master_password, char *token_out, size_t token_len);

/* 修改主密码：必须在已解锁状态下调用，用新密钥重新加密全部条目并签发新令牌。
 * 中途失败会尽力回滚（用旧密钥重写条目并恢复旧 salt）。
 * 注意：这是"全量重写"操作，期间不要断电。 */
esp_err_t vault_change_password(const char *old_password, const char *new_password,
                                char *token_out, size_t token_len);

/* 是否已解锁 */
bool vault_is_unlocked(void);

/* 锁定 vault（清除内存中的密钥） */
void vault_lock(void);

/* 验证会话令牌（同时刷新超时） */
bool vault_validate_token(const char *token);

/* ── 结构化凭证存储 ── */
int vault_cred_count(void);
esp_err_t vault_get_cred(int index, vault_cred_t *out);
esp_err_t vault_add_cred(const vault_cred_t *cred);
esp_err_t vault_update_cred(int index, const vault_cred_t *cred);
esp_err_t vault_delete_cred(int index);

/* ── 任意字符串 KV 存储 ── */
int vault_kv_count(void);
esp_err_t vault_kv_set(const char *key, const char *value);
esp_err_t vault_kv_get(const char *key, char *value_out, size_t max_len);
esp_err_t vault_kv_delete(const char *key);
/* 列出所有 key，keys_out 是 char[VAULT_MAX_KV_KEY_LEN] 数组，max_keys 为数组容量 */
esp_err_t vault_kv_list(char keys_out[][VAULT_MAX_KV_KEY_LEN], int max_keys, int *count_out);

/* ── 备份 / 恢复 ──
 *
 * 备份内容是"密文 + salt + 验证块"，不含主密码也不含任何明文，
 * 因此备份文件离线保存是安全的（没有主密码依然解不开）。
 *
 * 二进制布局（全部小端、逐字节写入，不做结构体映射）：
 *   "KVBK" | u8 version | u32 payload_len | payload | u32 crc32(payload)
 * payload:
 *   u32 cred_cnt | u32 kv_cnt
 *   u32 salt_len  | salt_blob
 *   u32 verif_len | verif_blob
 *   cred_cnt x (u32 len | blob)
 *   kv_cnt   x (u32 len | blob)
 *
 * 每个 blob 都是仓库里的原始形态（尾部含 CRC32），可直接 dual_set_blob 写回。
 */

/* 导出当前仓库为备份二进制（*out_buf 由 malloc 分配，调用方 free 后应清零） */
esp_err_t vault_export(uint8_t **out_buf, size_t *out_len);

/* 用备份二进制整库恢复：先校验 CRC 与主密码，通过后才落盘覆盖。
 * 成功返回后 vault 处于锁定态，需要用该主密码重新解锁。 */
esp_err_t vault_import(const uint8_t *buf, size_t len, const char *master_password);

/* 生成随机密码 */
esp_err_t vault_generate_password(char *out, size_t len,
                                   bool upper, bool lower,
                                   bool digits, bool symbols);

/* 重置 vault（清除所有数据，两个分区都清） */
esp_err_t vault_reset(void);

/* 安全清零内存（不被编译器优化掉） */
void vault_secure_zero(void *p, size_t n);


