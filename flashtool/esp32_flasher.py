"""
KEYVAULT-ESP32 Flasher Module (ESP32-S3 专用固件烧录引擎)
==========================================================
支持 ESP32-S3 预编译固件的多段分区烧录与擦除：
- bootloader.bin -> 0x0
- partitions.bin -> 0x8000
- firmware.bin   -> 0x10000

支持：
1. 自动检测可用串口与设备描述
2. 自动检测并安装 esptool
3. 线程安全后台烧录与实时输出解析
4. 全片 Flash 擦除
"""

import os
import sys
import subprocess
import threading
import time
import re
import glob
import shutil
from typing import Callable, List, Optional, Dict, Any


class ESP32FlasherError(Exception):
    """烧录器错误异常"""
    pass


class ESP32Flasher:
    """
    ESP32-S3 固件烧录核心引擎
    """

    # 默认固件目录名
    DEFAULT_FIRMWARE_DIR = "firmware"

    # esptool.py 参数
    DEFAULT_FLASH_SIZE = "4MB"
    DEFAULT_FLASH_FREQ = "80m"
    DEFAULT_FLASH_MODE = "dio"
    DEFAULT_CHIP = "esp32s3"

    # ESP32-S3 4MB Flash 标准分区烧录映射
    FLASH_LAYOUT: Dict[str, str] = {
        "bootloader.bin": "0x0",
        "partitions.bin": "0x8000",
        "firmware.bin":   "0x10000",
    }

    def __init__(
        self,
        project_path: Optional[str] = None,
        firmware_dir: Optional[str] = None,
        log_callback: Optional[Callable[[str, str], None]] = None,
    ):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.flashtool_dir = base_dir

        if project_path is None:
            self.project_path = os.path.dirname(base_dir)
        else:
            self.project_path = project_path

        self.firmware_dir = firmware_dir or self.DEFAULT_FIRMWARE_DIR
        self.log_callback = log_callback or self._default_log

        self._flash_thread: Optional[threading.Thread] = None
        self._cancel_event = threading.Event()

        self._cached_ports: List[Dict[str, str]] = []
        self._last_port_scan = 0.0

        self._firmware_dict: Optional[Dict[str, str]] = None
        self._esptool_cmd: Optional[List[str]] = None

    def _default_log(self, level: str, msg: str):
        print(f"[{level}] {msg}", file=sys.stderr if level == "ERROR" else sys.stdout)

    def _log(self, level: str, msg: str):
        self.log_callback(level, msg)

    # ============================================================
    # 固件文件检测
    # ============================================================

    def find_firmware(self) -> Optional[Dict[str, str]]:
        """
        查找固件文件并返回 {烧录地址: 绝对路径} 字典
        """
        candidates = [
            os.path.join(self.flashtool_dir, self.firmware_dir),
            os.path.join(self.project_path, self.firmware_dir),
            os.path.join(self.project_path, ".pio", "build-usb4", "esp32-s3-devkitm-1"),
            os.path.join(self.project_path, ".pio", "build", "esp32-s3-devkitm-1"),
        ]

        found_layout: Dict[str, str] = {}

        for root in candidates:
            if not os.path.isdir(root):
                continue

            all_matched = True
            temp_layout = {}
            for fname, addr in self.FLASH_LAYOUT.items():
                fpath = os.path.join(root, fname)
                if os.path.isfile(fpath) and os.path.getsize(fpath) > 0:
                    temp_layout[addr] = fpath
                else:
                    all_matched = False
                    break

            if all_matched:
                found_layout = temp_layout
                self._firmware_dict = found_layout
                return found_layout

        self._firmware_dict = None
        return None

    def get_firmware_info(self) -> Dict[str, Any]:
        """获取固件信息汇总"""
        fw = self.find_firmware()
        if not fw:
            return {"ready": False, "files": [], "total_size": 0}

        files_info = []
        total_size = 0
        for addr, path in fw.items():
            sz = os.path.getsize(path)
            total_size += sz
            files_info.append({
                "name": os.path.basename(path),
                "addr": addr,
                "size": sz,
                "path": path
            })

        return {
            "ready": True,
            "files": files_info,
            "total_size": total_size,
        }

    # ============================================================
    # 串口检测
    # ============================================================

    def list_ports(self, force_refresh: bool = False) -> List[Dict[str, str]]:
        """
        扫描系统中可用的串口
        Returns:
            [{"port": "COM3", "desc": "..."}, ...]
        """
        now = time.time()
        if not force_refresh and self._cached_ports and (now - self._last_port_scan < 2.0):
            return self._cached_ports

        ports = []
        try:
            import serial.tools.list_ports
            for p in serial.tools.list_ports.comports():
                desc = p.description or ""
                hwid = p.hwid or ""
                ports.append({
                    "port": p.device,
                    "desc": desc,
                    "hwid": hwid
                })
        except ImportError:
            # 没有 pyserial 时退化到平台检测
            if sys.platform == "win32":
                import winreg
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DEVICEMAP\SERIALCOMM")
                    for i in range(256):
                        try:
                            val_name, port_name, _ = winreg.EnumValue(key, i)
                            ports.append({"port": port_name, "desc": val_name, "hwid": ""})
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except Exception:
                    pass
            else:
                for pat in ["/dev/ttyUSB*", "/dev/ttyACM*", "/dev/cu.usb*"]:
                    for dev in glob.glob(pat):
                        ports.append({"port": dev, "desc": dev, "hwid": ""})

        self._cached_ports = ports
        self._last_port_scan = now
        return ports

    # ============================================================
    # esptool 检测与安装
    # ============================================================

    def get_esptool_command(self) -> Optional[List[str]]:
        """检测可用的 esptool 命令（智能支持 Conda、venv、PlatformIO 环境）"""
        # 1. 检测当前环境 (包括激活的 conda / venv) 中的 python -m esptool
        try:
            p = subprocess.run(
                [sys.executable, "-m", "esptool", "version"],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            )
            if p.returncode == 0:
                return [sys.executable, "-m", "esptool"]
        except Exception:
            pass

        # 2. 检测全局 PATH 中的 esptool / esptool.py
        for cmd in ["esptool.py", "esptool"]:
            if shutil.which(cmd):
                try:
                    p = subprocess.run(
                        [cmd, "version"],
                        capture_output=True,
                        text=True,
                        creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
                    )
                    if p.returncode == 0:
                        return [cmd]
                except Exception:
                    pass

        # 3. 扫描已存在的虚拟环境 (venv / conda / PlatformIO)
        home = os.path.expanduser("~")
        candidate_pythons = [
            # 激活的 conda 路径
            os.path.join(os.environ.get("CONDA_PREFIX", ""), "python.exe") if os.environ.get("CONDA_PREFIX") else None,
            # 激活的 venv 路径
            os.path.join(os.environ.get("VIRTUAL_ENV", ""), "Scripts", "python.exe") if os.environ.get("VIRTUAL_ENV") else None,
            # 本地 .venv
            os.path.join(self.flashtool_dir, ".venv", "Scripts", "python.exe"),
            os.path.join(self.project_path, ".venv", "Scripts", "python.exe"),
            # PlatformIO 默认内置 Python 环境
            os.path.join(home, ".platformio", "penv", "Scripts", "python.exe"),
        ]

        for py in filter(None, candidate_pythons):
            if os.path.isfile(py):
                try:
                    p = subprocess.run(
                        [py, "-m", "esptool", "version"],
                        capture_output=True,
                        text=True,
                        creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
                    )
                    if p.returncode == 0:
                        return [py, "-m", "esptool"]
                except Exception:
                    pass

        # 4. 检测 PlatformIO tool-esptoolpy 脚本 (直接使用当前 python 执行)
        pio_esptool_py = os.path.join(home, ".platformio", "packages", "tool-esptoolpy", "esptool.py")
        if os.path.isfile(pio_esptool_py):
            try:
                p = subprocess.run(
                    [sys.executable, pio_esptool_py, "version"],
                    capture_output=True,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
                )
                if p.returncode == 0:
                    return [sys.executable, pio_esptool_py]
            except Exception:
                pass

        return None

    def install_esptool(self) -> bool:
        """通过 pip 安装 esptool"""
        self._log("INFO", "正在尝试通过 pip 安装 esptool...")
        try:
            cmd = [sys.executable, "-m", "pip", "install", "esptool", "pyserial"]
            p = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            )
            while True:
                line = p.stdout.readline()
                if not line and p.poll() is not None:
                    break
                if line:
                    self._log("INFO", line.strip())
            return p.returncode == 0
        except Exception as e:
            self._log("ERROR", f"安装失败: {e}")
            return False

    # ============================================================
    # 烧录功能
    # ============================================================

    def flash(
        self,
        port: str,
        baud: int = 921600,
        chip: Optional[str] = None,
        background: bool = True,
        on_done: Optional[Callable[[bool, Optional[str]], None]] = None,
    ) -> bool:
        """
        开始烧录固件
        """
        fw = self.find_firmware()
        if not fw:
            raise ESP32FlasherError("未找到完整固件文件！请确认 firmware 目录下包含 bootloader.bin, partitions.bin, firmware.bin")

        esptool_cmd = self.get_esptool_command()
        if not esptool_cmd:
            raise ESP32FlasherError("未检测到 esptool 工具！请先点击【安装 esptool】或在终端运行 pip install esptool")

        if not port:
            raise ESP32FlasherError("请选择目标串口号！")

        target_chip = chip or self.DEFAULT_CHIP

        # 构建命令行
        cmd = list(esptool_cmd)
        cmd.extend([
            "--chip", target_chip,
            "--port", port,
            "--baud", str(baud),
            "--before", "default_reset",
            "--after", "hard_reset",
            "write_flash",
            "--flash_mode", self.DEFAULT_FLASH_MODE,
            "--flash_size", self.DEFAULT_FLASH_SIZE,
            "--flash_freq", self.DEFAULT_FLASH_FREQ,
        ])

        # 按地址顺序追加文件
        sorted_addrs = sorted(fw.keys(), key=lambda a: int(a, 16))
        for addr in sorted_addrs:
            cmd.extend([addr, fw[addr]])

        def _worker():
            self._cancel_event.clear()
            self._log("INFO", f"开始烧录到 {port}，芯片: {target_chip.upper()}，波特率: {baud}...")
            self._log("INFO", "若连接卡顿，请按住开发板 BOOT 键，轻按一下 RST 键进入下载模式。")
            success = False
            err_msg = None
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
                )

                while True:
                    if self._cancel_event.is_set():
                        proc.terminate()
                        err_msg = "用户取消烧录"
                        break

                    line = proc.stdout.readline()
                    if not line and proc.poll() is not None:
                        break

                    if line:
                        clean_line = line.strip()
                        if clean_line:
                            if "Writing at" in clean_line or "Hash of data verified" in clean_line:
                                self._log("OK", clean_line)
                            elif "Connecting" in clean_line:
                                self._log("WARN", clean_line)
                            elif "A fatal error occurred" in clean_line or "Error" in clean_line:
                                self._log("ERROR", clean_line)
                                err_msg = clean_line
                            else:
                                self._log("INFO", clean_line)

                proc.wait()
                if proc.returncode == 0:
                    success = True
                    self._log("OK", "🎉 固件烧录成功！ESP32-S3 设备已自动复位启动。")
                else:
                    if not err_msg:
                        err_msg = f"烧录失败，进程退出码: {proc.returncode}"
                    self._log("ERROR", err_msg)

            except Exception as e:
                err_msg = str(e)
                self._log("ERROR", f"执行异常: {err_msg}")

            if on_done:
                on_done(success, err_msg)

        if background:
            self._flash_thread = threading.Thread(target=_worker, daemon=True)
            self._flash_thread.start()
            return True
        else:
            _worker()
            return True

    # ============================================================
    # 全片擦除
    # ============================================================

    def erase_flash(
        self,
        port: str,
        baud: int = 921600,
        chip: Optional[str] = None,
        background: bool = True,
        on_done: Optional[Callable[[bool, Optional[str]], None]] = None,
    ) -> bool:
        """全片擦除 Flash"""
        esptool_cmd = self.get_esptool_command()
        if not esptool_cmd:
            raise ESP32FlasherError("未检测到 esptool 工具！")
        if not port:
            raise ESP32FlasherError("请选择目标串口号！")

        target_chip = chip or self.DEFAULT_CHIP
        cmd = list(esptool_cmd)
        cmd.extend([
            "--chip", target_chip,
            "--port", port,
            "--baud", str(baud),
            "erase_flash",
        ])

        def _worker():
            self._cancel_event.clear()
            self._log("WARN", f"正在擦除 {port} 的整块 Flash 闪存（请耐心等待数十秒）...")
            success = False
            err_msg = None
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
                )

                while True:
                    if self._cancel_event.is_set():
                        proc.terminate()
                        err_msg = "用户取消擦除"
                        break
                    line = proc.stdout.readline()
                    if not line and proc.poll() is not None:
                        break
                    if line:
                        clean_line = line.strip()
                        if clean_line:
                            self._log("INFO", clean_line)

                proc.wait()
                if proc.returncode == 0:
                    success = True
                    self._log("OK", "✅ Flash 闪存擦除成功！所有数据已彻底清除。")
                else:
                    err_msg = f"擦除失败，退出码: {proc.returncode}"
                    self._log("ERROR", err_msg)
            except Exception as e:
                err_msg = str(e)
                self._log("ERROR", f"执行异常: {err_msg}")

            if on_done:
                on_done(success, err_msg)

        if background:
            self._flash_thread = threading.Thread(target=_worker, daemon=True)
            self._flash_thread.start()
            return True
        else:
            _worker()
            return True
