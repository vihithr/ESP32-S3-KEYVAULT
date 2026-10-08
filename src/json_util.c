/*
 * json_util.c —— 极简 JSON 读写辅助实现
 *
 * 只处理本项目实际用到的形态：扁平/浅嵌套对象、字符串/整数/布尔值。
 * 不做完整 JSON 语法校验，但对「字符串值」的边界与转义做严格处理：
 *   - 取值时先定位到值起始，再按转义规则扫描到真正的结束引号
 *     （早期实现直接用 strchr 找 '"'，遇到 \" 会提前截断，密码里带引号即丢数据）
 */
#include "json_util.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

size_t json_escape_str(char *dst, size_t dst_len, const char *src)
{
    size_t o = 0;
    if (dst_len == 0) {
        return 0;
    }
    for (const unsigned char *p = (const unsigned char *)src; *p != '\0'; p++) {
        char rep[8];
        const char *s = NULL;
        switch (*p) {
        case '"':  s = "\\\""; break;
        case '\\': s = "\\\\"; break;
        case '\n': s = "\\n"; break;
        case '\r': s = "\\r"; break;
        case '\t': s = "\\t"; break;
        default:
            if (*p < 0x20) {
                snprintf(rep, sizeof(rep), "\\u%04x", *p);
                s = rep;
            }
            break;
        }
        size_t n = s ? strlen(s) : 1;
        if (o + n + 1 > dst_len) {
            break;                      /* 保留结尾 NUL */
        }
        if (s) {
            memcpy(dst + o, s, n);
        } else {
            dst[o] = (char)*p;
        }
        o += n;
    }
    dst[o] = '\0';
    return o;
}

/* 码点 → UTF-8（本项目的 UI 全量 UTF-8，BMP 已足够） */
static size_t utf8_encode(uint32_t cp, char out[3])
{
    if (cp < 0x80) {
        out[0] = (char)cp;
        return 1;
    }
    if (cp < 0x800) {
        out[0] = (char)(0xC0 | (cp >> 6));
        out[1] = (char)(0x80 | (cp & 0x3F));
        return 2;
    }
    out[0] = (char)(0xE0 | (cp >> 12));
    out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
    out[2] = (char)(0x80 | (cp & 0x3F));
    return 3;
}

static int hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

size_t json_unescape_str(char *out, size_t out_len, const char *src, size_t src_len)
{
    size_t o = 0, i = 0;
    if (out_len == 0) {
        return 0;
    }
    while (i < src_len && src[i] != '\0') {
        char c = src[i++];
        if (c != '\\') {
            if (o + 1 >= out_len) break;
            out[o++] = c;
            continue;
        }
        if (i >= src_len) break;

        char e = src[i++];
        char lit;
        switch (e) {
        case 'n': lit = '\n'; break;
        case 'r': lit = '\r'; break;
        case 't': lit = '\t'; break;
        case 'b': lit = '\b'; break;
        case 'f': lit = '\f'; break;
        case '"':
        case '\\':
        case '/': lit = e; break;
        case 'u': {
            if (i + 4 > src_len) { out[o] = '\0'; return o; }
            uint32_t cp = 0;
            bool ok = true;
            for (int k = 0; k < 4; k++) {
                int v = hex_val(src[i + k]);
                if (v < 0) { ok = false; break; }
                cp = (cp << 4) | (uint32_t)v;
            }
            i += 4;
            if (!ok) { out[o] = '\0'; return o; }   /* 非法 \u 序列：停止解析 */
            char buf[3];
            size_t n = utf8_encode(cp, buf);
            if (o + n + 1 > out_len) { out[o] = '\0'; return o; }
            memcpy(out + o, buf, n);
            o += n;
            continue;
        }
        default:
            /* 未知转义：按字面保留反斜杠与后续字符 */
            if (o + 2 >= out_len) { out[o] = '\0'; return o; }
            out[o++] = '\\';
            out[o++] = e;
            continue;
        }
        if (o + 1 >= out_len) { out[o] = '\0'; return o; }
        out[o++] = lit;
    }
    out[o] = '\0';
    return o;
}

/* 从 JSON 串内容的起始位置扫描到真正的结束引号（跳过 \\ 转义） */
static const char *json_find_str_end(const char *p)
{
    for (; *p != '\0'; p++) {
        if (*p == '\\') {
            p++;
            if (*p == '\0') {
                return NULL;
            }
        } else if (*p == '"') {
            return p;
        }
    }
    return NULL;
}

static const char *json_find_field_colon(const char *json, const char *field)
{
    if (!json || !field) return NULL;
    char key[48];
    snprintf(key, sizeof(key), "\"%s\"", field);
    size_t klen = strlen(key);
    const char *p = json;
    while ((p = strstr(p, key)) != NULL) {
        const char *after = p + klen;
        while (*after == ' ' || *after == '\t' || *after == '\r' || *after == '\n') {
            after++;
        }
        if (*after == ':') {
            after++;
            while (*after == ' ' || *after == '\t' || *after == '\r' || *after == '\n') {
                after++;
            }
            return after;
        }
        p += klen;
    }
    return NULL;
}

bool json_get_str_field(const char *json, const char *field, char *out, size_t out_len)
{
    if (!json || !out || out_len == 0) {
        return false;
    }
    const char *p = json_find_field_colon(json, field);
    if (!p || *p != '"') {
        return false;
    }
    p++;
    const char *end = json_find_str_end(p);
    if (!end) {
        return false;
    }
    json_unescape_str(out, out_len, p, (size_t)(end - p));
    return true;
}

bool json_locate_str_field(const char *json, const char *field, const char **start, size_t *len)
{
    if (!json || !start || !len) {
        return false;
    }
    const char *p = json_find_field_colon(json, field);
    if (!p || *p != '"') {
        return false;
    }
    p++;
    const char *end = json_find_str_end(p);
    if (!end) {
        return false;
    }
    *start = p;
    *len = (size_t)(end - p);
    return true;
}

bool json_get_int_field(const char *json, const char *field, int *out)
{
    if (!json || !out) {
        return false;
    }
    const char *p = json_find_field_colon(json, field);
    if (!p) {
        return false;
    }
    *out = atoi(p);
    return true;
}

bool json_get_bool_field(const char *json, const char *field, bool *out)
{
    if (!json || !out) {
        return false;
    }
    const char *p = json_find_field_colon(json, field);
    if (!p) {
        return false;
    }
    if (strncmp(p, "true", 4) == 0) {
        *out = true;
    } else if (strncmp(p, "false", 5) == 0) {
        *out = false;
    } else {
        return false;                    /* 非布尔：不猜测，交给调用方走默认值 */
    }
    return true;
}
