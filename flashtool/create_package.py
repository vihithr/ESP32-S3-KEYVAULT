"""
KEYVAULT-ESP32 固件打包与分发工具
==================================
参照成熟工作流，自动化完成：
1. 编译嵌入式前端并构建 PlatformIO 固件
2. 提取并同步 bootloader / partitions / firmware 至 flashtool/firmware/
3. 自动打包生成便携版分发 ZIP 压缩包 (包含 GUI 烧录器、批处理与固件)

使用方法：
    python flashtool/create_package.py
"""

import os
import sys
import shutil
import subprocess
import time
import zipfile

# 解决 Windows 控制台默认 GBK 编码对 emoji / 特殊字符的报错
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

FLASHTOOL_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(FLASHTOOL_DIR)
FIRMWARE_DIR = os.path.join(FLASHTOOL_DIR, "firmware")
PIO_BUILD_DIR = os.path.join(PROJECT_ROOT, ".pio", "build-usb4", "esp32-s3-devkitm-1")


def log(msg: str):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}")


def find_pio() -> str:
    """查找可用的 pio 命令"""
    # 1. 检查环境变量中的 pio
    pio_path = shutil.which("pio")
    if pio_path:
        return pio_path

    # 2. 检查默认 PlatformIO penv
    home = os.path.expanduser("~")
    candidates = [
        os.path.join(home, ".platformio", "penv", "Scripts", "pio.exe"),
        os.path.join(home, ".platformio", "penv", "bin", "pio"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c

    return "pio"


def compile_firmware() -> bool:
    """编译固件"""
    log("=" * 50)
    log("正在生成最新嵌入式 Web 资源...")
    gen_script = os.path.join(PROJECT_ROOT, "tools", "gen_web_content.py")
    if os.path.exists(gen_script):
        ret = subprocess.run([sys.executable, gen_script], cwd=PROJECT_ROOT)
        if ret.returncode != 0:
            log("❌ 生成网页资源失败！")
            return False

    log("正在通过 PlatformIO 编译固件...")
    pio_cmd = find_pio()
    ret = subprocess.run([pio_cmd, "run"], cwd=PROJECT_ROOT)
    if ret.returncode != 0:
        log("❌ PlatformIO 编译失败！")
        return False

    log("✅ 固件编译成功！")
    return True


def copy_firmware() -> bool:
    """复制固件至 firmware/ 目录"""
    log("=" * 50)
    log("正在同步固件到 flashtool/firmware 目录...")
    os.makedirs(FIRMWARE_DIR, exist_ok=True)

    bins = ["bootloader.bin", "partitions.bin", "firmware.bin"]
    for b in bins:
        src = os.path.join(PIO_BUILD_DIR, b)
        dst = os.path.join(FIRMWARE_DIR, b)
        if not os.path.exists(src):
            log(f"❌ 找不到编译产物: {src}")
            return False
        shutil.copy2(src, dst)
        size_kb = os.path.getsize(dst) / 1024
        log(f"   已复制: {b} -> {size_kb:.1f} KB")

    log("✅ 固件文件同步完毕！")
    return True


def create_package() -> str:
    """创建便携分发包 ZIP"""
    log("=" * 50)
    log("正在创建分发 ZIP 压缩包...")

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    zip_name = f"KEYVAULT-ESP32-v1.1.0-Flashtool_{timestamp}.zip"
    zip_path = os.path.join(FLASHTOOL_DIR, zip_name)

    # 包含的文件
    files_to_pack = [
        (os.path.join(FLASHTOOL_DIR, "esp32_flash_gui.py"), "esp32_flash_gui.py"),
        (os.path.join(FLASHTOOL_DIR, "esp32_flasher.py"), "esp32_flasher.py"),
        (os.path.join(FLASHTOOL_DIR, "flash_gui.bat"), "flash_gui.bat"),
        (os.path.join(FLASHTOOL_DIR, "flash.bat"), "flash.bat"),
        (os.path.join(FLASHTOOL_DIR, "requirements.txt"), "requirements.txt"),
    ]

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # 打包 firmware 目录
        for fname in ["bootloader.bin", "partitions.bin", "firmware.bin"]:
            fpath = os.path.join(FIRMWARE_DIR, fname)
            if os.path.exists(fpath):
                zf.write(fpath, f"firmware/{fname}")
                log(f"   添加: firmware/{fname}")

        # 打包工具脚本
        for src, arc in files_to_pack:
            if os.path.exists(src):
                zf.write(src, arc)
                log(f"   添加: {arc}")

    # 同时创建一个无时间戳的标准 release 包用于发布
    std_zip = os.path.join(FLASHTOOL_DIR, "ESP32-S3-KEYVAULT-v1.1.0-release.zip")
    shutil.copy2(zip_path, std_zip)

    sz_mb = os.path.getsize(zip_path) / (1024 * 1024)
    log(f"✅ 分发包创建成功！大小: {sz_mb:.2f} MB")
    log(f"   文件路径: {zip_path}")
    return zip_path


def main():
    action = None
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        if arg in ["--compile", "-c", "1"]:
            action = "1"
        elif arg in ["--sync", "-s", "2"]:
            action = "2"
        elif arg in ["--pack", "-p", "3"]:
            action = "3"
        elif arg in ["--all", "-a", "4"]:
            action = "4"

    if not action:
        print("=" * 50)
        print("  KEYVAULT-ESP32 固件打包与分发工具")
        print("=" * 50)
        print("1. 仅编译固件")
        print("2. 编译并同步到 firmware/ 目录")
        print("3. 直接打包已有固件为 ZIP 分发包")
        print("4. [推荐] 完整流水线 (编译 + 同步 + 打包)")
        print()
        try:
            choice = input("请选择操作 (1-4，直接回车默认为 4): ").strip()
            action = choice if choice else "4"
        except (EOFError, KeyboardInterrupt):
            action = "4"

    if action == "1":
        compile_firmware()
    elif action == "2":
        if compile_firmware():
            copy_firmware()
    elif action == "3":
        create_package()
    elif action == "4":
        if compile_firmware() and copy_firmware():
            create_package()
    else:
        print("无效选项")


if __name__ == "__main__":
    main()
