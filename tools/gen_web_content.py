#!/usr/bin/env python3
"""从 src/index.html 生成 src/web_content.c（单次 C 转义）。

- pio run 时会由 platformio.ini 的 extra_scripts 自动调用（pre:）
- 也可手动执行:  python tools/gen_web_content.py

只做一次转义： \\ -> \\\\ , " -> \\" , 换行 -> \\n 。
多转义一层会让浏览器收到非法 JS（整段 <script> 不执行 -> 全屏空白）。
"""
import os

try:                                    # 被 PlatformIO 当 extra_script 执行时（SCons 注入 env）
    import SCons.Script  # noqa: F401
    Import("env")                       # noqa: F821
    ROOT = env.subst("$PROJECT_DIR")    # noqa: F821
except Exception:                       # 手动执行: python tools/gen_web_content.py
    ROOT = os.getcwd()
    if not os.path.isfile(os.path.join(ROOT, "src", "index.html")):
        ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SRC = os.path.join(ROOT, "src", "index.html")
DST = os.path.join(ROOT, "src", "web_content.c")

TEMPLATE = """/*
 * web_content.c —— embedded Web UI HTML content
 * auto-generated from index.html by tools/gen_web_content.py —— 请勿手改
 */
#include "web_content.h"

const char WEB_INDEX_HTML[] = "%s";
const unsigned int WEB_INDEX_HTML_LEN = sizeof(WEB_INDEX_HTML) - 1;
"""


def c_escape(text):
    out = []
    for ch in text:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 0x20:
            out.append("\\%03o" % ord(ch))
        else:
            out.append(ch)
    return "".join(out)


def main():
    with open(SRC, "r", encoding="utf-8") as f:
        html = f.read()                      # 通用换行：CRLF -> LF

    content = TEMPLATE % c_escape(html)

    # 幂等：内容没变就不写文件，否则每次构建都会因 mtime 变化触发
    # web_content.c（以及依赖它的目标）无谓重编译
    try:
        with open(DST, "r", encoding="utf-8") as f:
            if f.read() == content:
                # 输出保持 ASCII：Windows 控制台多为 GBK，中文会显示成乱码
                print("[gen_web_content] %s unchanged, skip writing"
                      % os.path.relpath(DST, ROOT))
                return
    except (IOError, OSError):
        pass

    with open(DST, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)

    print("[gen_web_content] %s -> %s (%d bytes)"
          % (os.path.relpath(SRC, ROOT), os.path.relpath(DST, ROOT),
             len(html.encode("utf-8"))))


main()
