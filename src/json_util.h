/*
 * json_util —— 极简 JSON 读写辅助（仅面向本项目自控的短报文）
 *
 * 设计目标：
 *   - 一份实现同时服务 HTTP 请求解析（main.c）与落盘序列化（keyvault.c），
 *     避免两处解析器行为不一致导致的静默数据损坏
 *   - 写入侧必须转义、读取侧必须反转义：否则密码中的 " \ 换行会破坏 JSON 结构
 *   - 无动态分配，全部在调用方提供的缓冲区内完成，空间不足时截断并保证 NUL 结尾
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 把 src 转义为可嵌入 JSON 双引号串的内容（不含外层引号）。
 * 返回写入 dst 的字符数（不含结尾 NUL）；空间不足时截断。 */
size_t json_escape_str(char *dst, size_t dst_len, const char *src);

/* 把 JSON 串内容（不含外层引号）反转义写入 out。
 * src_len 为源长度；返回写入 out 的字符数（不含结尾 NUL）；空间不足时截断。 */
size_t json_unescape_str(char *out, size_t out_len, const char *src, size_t src_len);

/* 从 JSON 文本中提取字符串字段值（自动反转义）。字段不存在返回 false。 */
bool json_get_str_field(const char *json, const char *field, char *out, size_t out_len);

/* 定位字符串字段的"原始值"区间（不拷贝、不反转义）。
 * 用于超大字段（如备份的 base64），避免在内存里再复制一份。
 * 找到时 *start 指向首字符、*len 为字符数（不含结束引号）。 */
bool json_locate_str_field(const char *json, const char *field, const char **start, size_t *len);

/* 从 JSON 文本中提取整数字段值。字段不存在返回 false（*out 不变）。 */
bool json_get_int_field(const char *json, const char *field, int *out);

/* 从 JSON 文本中提取布尔字段值。字段不存在返回 false（*out 不变）。 */
bool json_get_bool_field(const char *json, const char *field, bool *out);

#ifdef __cplusplus
}
#endif
