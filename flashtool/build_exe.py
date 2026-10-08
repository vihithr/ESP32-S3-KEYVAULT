"""
KEYVAULT-ESP32 PyInstaller 打包构建脚本
========================================
将 esp32_flash_gui.py 与固件打包为单个开箱即用的 Windows 可执行程序 (.exe)。
小白用户完全无需安装 Python、无需配置环境，双击即可烧录！

使用方法：
    python flashtool/build_exe.py
"""

import os
import sys
import shutil
import subprocess

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

FLASHTOOL_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(FLASHTOOL_DIR)
FIRMWARE_DIR = os.path.join(FLASHTOOL_DIR, "firmware")
GUI_SCRIPT = os.path.join(FLASHTOOL_DIR, "esp32_flash_gui.py")
OUTPUT_EXE_NAME = "KEYVAULT-Flasher"

# 避免混入臃肿科学计算与庞大 UI 库（如果在包含庞大第三方库的 Python 环境中运行）
EXCLUDE_MODULES = [
    "numpy", "scipy", "matplotlib", "pandas", "torch", "tensorflow",
    "IPython", "jupyter", "notebook", "sphinx", "pytest", "PIL", "cv2",
    "PyQt5", "PyQt6", "PySide2", "PySide6", "wx", "tornado", "zmq",
    "sqlalchemy", "paramiko", "numba", "skimage", "sklearn"
]


def get_builder_python() -> str:
    """优先使用专用的纯净 venv 环境以打包最小体积的 EXE；否则使用当前 Python"""
    clean_venv_py = os.path.join(FLASHTOOL_DIR, ".venv_build", "Scripts", "python.exe")
    if os.path.isfile(clean_venv_py):
        return clean_venv_py
    return sys.executable


def check_pyinstaller(py_exe: str) -> bool:
    try:
        ret = subprocess.run([py_exe, "-c", "import PyInstaller"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if ret.returncode == 0:
            return True
    except Exception:
        pass

    print("[提示] 正在安装 PyInstaller...")
    ret = subprocess.run([py_exe, "-m", "pip", "install", "pyinstaller"])
    return ret.returncode == 0


def build():
    print("=" * 60)
    print("  KEYVAULT-ESP32 单文件 EXE 构建工具")
    print("=" * 60)

    py_exe = get_builder_python()
    print(f"[环境] 打包 Python 解释器: {py_exe}")

    if not check_pyinstaller(py_exe):
        print("[错误] 未能成功安装或加载 PyInstaller！")
        return False

    if not os.path.isdir(FIRMWARE_DIR):
        print(f"[错误] 未找到固件目录: {FIRMWARE_DIR}")
        return False

    # 构造 PyInstaller 命令行
    # Windows 下 --add-data 的分隔符为分号 ';'
    add_data_arg = f"{FIRMWARE_DIR};firmware"

    cmd = [
        py_exe, "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--windowed",
        "--name", OUTPUT_EXE_NAME,
        "--add-data", add_data_arg,
        "--hidden-import", "esptool",
        "--hidden-import", "serial",
        "--hidden-import", "serial.tools.list_ports",
        "--hidden-import", "tkinter",
        "--hidden-import", "tkinter.ttk",
        "--hidden-import", "tkinter.messagebox",
        "--hidden-import", "tkinter.scrolledtext",
    ]

    for mod in EXCLUDE_MODULES:
        cmd.extend(["--exclude-module", mod])

    cmd.append(GUI_SCRIPT)

    print(f"[执行] 正在打包...")
    print("[提示] 正在封装 Python 解释器、Tkinter、esptool 与完整固件，请稍候 1-2 分钟...")
    print()

    ret = subprocess.run(cmd, cwd=FLASHTOOL_DIR)
    if ret.returncode != 0:
        print("\n[错误] PyInstaller 打包失败！")
        return False

    dist_dir = os.path.join(FLASHTOOL_DIR, "dist")
    exe_path = os.path.join(dist_dir, f"{OUTPUT_EXE_NAME}.exe")

    if os.path.isfile(exe_path):
        target_path = os.path.join(FLASHTOOL_DIR, f"{OUTPUT_EXE_NAME}.exe")
        shutil.copy2(exe_path, target_path)
        sz_mb = os.path.getsize(target_path) / (1024 * 1024)
        print()
        print("=" * 60)
        try:
            print(f"🎉 单文件 EXE 打包成功！")
        except Exception:
            print("[+] 单文件 EXE 打包成功！")
        print(f"   可执行文件: {target_path}")
        print(f"   体积: {sz_mb:.2f} MB")
        print("   小白用户无需安装任何 Python 环境，双击此 EXE 即可直接烧录！")
        print("=" * 60)
        return True
    else:
        print("[错误] 未找到生成的 exe 文件！")
        return False


if __name__ == "__main__":
    build()
