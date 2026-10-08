"""
KEYVAULT-ESP32 Firmware Flasher GUI
====================================
为 KEYVAULT-ESP32 深度定制的独立图形化固件烧录工具。
功能：
- 自动检测并展示多段固件完整性 (bootloader/partitions/firmware)
- 自动扫描并匹配 ESP32-S3 串口 (COM)
- 921600 / 460800 极速免驱动烧录
- 一键 Flash 全片安全擦除
- 内置实时串口日志监视器 (Serial Monitor)
"""

import os
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

# 导入烧录引擎
try:
    from esp32_flasher import ESP32Flasher, ESP32FlasherError
except ImportError:
    from flashtool.esp32_flasher import ESP32Flasher, ESP32FlasherError


class LogPanel:
    """日志面板组件"""
    COLORS = {
        "INFO": "#2c3e50",
        "OK": "#27ae60",
        "WARN": "#d35400",
        "ERROR": "#c0392b",
    }

    def __init__(self, text_widget: scrolledtext.ScrolledText):
        self.text = text_widget
        for level, color in self.COLORS.items():
            self.text.tag_configure(level, foreground=color)
        self.text.tag_configure("TIMESTAMP", foreground="#7f8c8d")
        self.text.configure(state=tk.DISABLED)

    def log(self, level: str, msg: str):
        self.text.configure(state=tk.NORMAL)
        ts = time.strftime("%H:%M:%S")
        self.text.insert(tk.END, f"[{ts}] ", "TIMESTAMP")
        self.text.insert(tk.END, f"[{level}] ", level)
        self.text.insert(tk.END, msg + "\n", level)
        self.text.see(tk.END)
        self.text.configure(state=tk.DISABLED)

    def clear(self):
        self.text.configure(state=tk.NORMAL)
        self.text.delete("1.0", tk.END)
        self.text.configure(state=tk.DISABLED)


class KEYVAULTFlashGUI(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("KEYVAULT-ESP32 固件烧录工具 v1.1.0")
        self.geometry("740x640")
        self.minsize(650, 550)

        # 居中显示
        self.center_window()

        # 初始化引擎
        self.flasher = ESP32Flasher(log_callback=self._log)
        self._is_flashing = False

        # 构建 UI
        self._build_ui()

        # 检查前置依赖与固件
        self.after(200, self._check_prerequisites)

    def center_window(self):
        self.update_idletasks()
        w = self.winfo_width()
        h = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (w // 2)
        y = (self.winfo_screenheight() // 2) - (h // 2)
        self.geometry(f"{w}x{h}+{x}+{y}")

    def _build_ui(self):
        main_frame = ttk.Frame(self, padding=12)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 标题栏
        title_frame = ttk.Frame(main_frame)
        title_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(
            title_frame,
            text="🔐 KEYVAULT-ESP32 烧录工具",
            font=("Microsoft YaHei", 15, "bold")
        ).pack(side=tk.LEFT)

        ttk.Label(
            title_frame,
            text="ESP32-S3 (4MB Flash)",
            font=("Microsoft YaHei", 9, "bold"),
            foreground="#2980b9"
        ).pack(side=tk.RIGHT, pady=6)

        # 固件状态卡片
        fw_box = ttk.LabelFrame(main_frame, text="固件状态", padding=10)
        fw_box.pack(fill=tk.X, pady=(0, 10))

        fw_top = ttk.Frame(fw_box)
        fw_top.pack(fill=tk.X)

        ttk.Label(fw_top, text="固件包状态:").pack(side=tk.LEFT)
        self.firmware_label = ttk.Label(
            fw_top,
            text="正在检测固件文件...",
            foreground="#7f8c8d"
        )
        self.firmware_label.pack(side=tk.LEFT, padx=(8, 0))

        ttk.Button(
            fw_top,
            text="🔄 刷新",
            command=self._refresh_firmware,
            width=6
        ).pack(side=tk.RIGHT)

        self.firmware_detail_label = ttk.Label(
            fw_box,
            text="",
            font=("Consolas", 8),
            foreground="#555555"
        )
        self.firmware_detail_label.pack(fill=tk.X, pady=(4, 0))

        # 烧录配置卡片
        cfg_box = ttk.LabelFrame(main_frame, text="烧录配置", padding=10)
        cfg_box.pack(fill=tk.X, pady=(0, 10))

        # 串口行
        port_row = ttk.Frame(cfg_box)
        port_row.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(port_row, text="串口 (COM):", width=12).pack(side=tk.LEFT)
        self.port_combo = ttk.Combobox(port_row, state="readonly", width=36)
        self.port_combo.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))

        ttk.Button(
            port_row,
            text="🔄 刷新串口",
            command=self._refresh_ports,
            width=10
        ).pack(side=tk.LEFT)

        # 波特率行
        baud_row = ttk.Frame(cfg_box)
        baud_row.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(baud_row, text="烧录波特率:", width=12).pack(side=tk.LEFT)
        self.baud_combo = ttk.Combobox(
            baud_row,
            values=["921600", "460800", "115200"],
            state="readonly",
            width=14
        )
        self.baud_combo.set("921600")
        self.baud_combo.pack(side=tk.LEFT)

        ttk.Label(
            baud_row,
            text="（ESP32-S3 推荐使用 921600 极速烧录）",
            foreground="#7f8c8d"
        ).pack(side=tk.LEFT, padx=(10, 0))

        # 硬件操作指引条
        hint_frame = ttk.Frame(cfg_box)
        hint_frame.pack(fill=tk.X, pady=(4, 0))
        ttk.Label(
            hint_frame,
            text="💡 提示：若连接超时，请按住板载 [BOOT] 键不放，轻按一下 [RST] 键松开，即可进入下载模式。",
            foreground="#e67e22",
            font=("Microsoft YaHei", 8)
        ).pack(side=tk.LEFT)

        # 操作按钮区
        btn_box = ttk.Frame(main_frame)
        btn_box.pack(fill=tk.X, pady=(0, 10))

        self.flash_btn = tk.Button(
            btn_box,
            text="⚡ 开始烧录固件",
            command=self._start_flash,
            bg="#27ae60",
            fg="white",
            activebackground="#219150",
            activeforeground="white",
            font=("Microsoft YaHei", 10, "bold"),
            relief=tk.FLAT,
            padx=16,
            pady=6,
            cursor="hand2"
        )
        self.flash_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.erase_btn = tk.Button(
            btn_box,
            text="🗑️ 全片擦除 Flash",
            command=self._start_erase,
            bg="#95a5a6",
            fg="white",
            activebackground="#7f8c8d",
            activeforeground="white",
            font=("Microsoft YaHei", 9),
            relief=tk.FLAT,
            padx=12,
            pady=6,
            cursor="hand2"
        )
        self.erase_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.monitor_btn = ttk.Button(
            btn_box,
            text="🔍 串口监视器",
            command=self._open_monitor,
            width=13
        )
        self.monitor_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.install_btn = ttk.Button(
            btn_box,
            text="📦 安装 esptool",
            command=self._install_esptool,
            width=13
        )
        self.install_btn.pack(side=tk.RIGHT)

        # 日志区域
        log_box = ttk.LabelFrame(main_frame, text="烧录进度与日志", padding=8)
        log_box.pack(fill=tk.BOTH, expand=True)

        text_widget = scrolledtext.ScrolledText(
            log_box,
            wrap=tk.WORD,
            font=("Consolas", 9),
            bg="#fdfefe",
            relief=tk.SOLID,
            bd=1
        )
        text_widget.pack(fill=tk.BOTH, expand=True)
        self.log_panel = LogPanel(text_widget)

        # 底部状态栏
        status_bar = ttk.Frame(main_frame)
        status_bar.pack(fill=tk.X, pady=(6, 0))

        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(status_bar, textvariable=self.status_var).pack(side=tk.LEFT)

        ttk.Button(
            status_bar,
            text="清空日志",
            command=self.log_panel.clear,
            width=8
        ).pack(side=tk.RIGHT)

    def _log(self, level: str, msg: str):
        self.after(0, self.log_panel.log, level, msg)

    # ============================================================
    # 状态与刷新
    # ============================================================

    def _check_prerequisites(self):
        self._refresh_firmware()
        self._refresh_ports()
        cmd = self.flasher.get_esptool_command()
        if cmd:
            self._log("OK", f"检测到烧录工具: {' '.join(cmd)}")
            self.install_btn.configure(state=tk.DISABLED)
        else:
            self._log("WARN", "未找到 esptool。如需烧录，请点击右上方【安装 esptool】按钮。")
            self.install_btn.configure(state=tk.NORMAL)

    def _refresh_firmware(self):
        info = self.flasher.get_firmware_info()
        if info["ready"]:
            total_kb = info["total_size"] / 1024
            self.firmware_label.configure(
                text=f"✅ 固件完整 (3个文件，共 {total_kb:.1f} KB)",
                foreground="#27ae60"
            )
            detail_str = " | ".join([f"{f['name']} ({f['addr']})" for f in info["files"]])
            self.firmware_detail_label.configure(text=detail_str)
        else:
            self.firmware_label.configure(
                text="❌ 缺少固件文件 (请检查 firmware 目录)",
                foreground="#c0392b"
            )
            self.firmware_detail_label.configure(text="需包含: bootloader.bin (0x0), partitions.bin (0x8000), firmware.bin (0x10000)")

    def _refresh_ports(self):
        ports = self.flasher.list_ports(force_refresh=True)
        if not ports:
            self.port_combo["values"] = []
            self.port_combo.set("未检测到串口设备")
            return

        values = []
        default_idx = 0
        for i, p in enumerate(ports):
            display = f"{p['port']} - {p['desc']}"
            values.append(display)
            # 优先匹配 USB JTAG / ESP / CP210 / CH340
            lower = display.lower()
            if any(k in lower for k in ["jtag", "esp", "usb-enhanced", "ch340", "cp210"]):
                default_idx = i

        self.port_combo["values"] = values
        self.port_combo.current(default_idx)

    def _get_selected_port(self) -> Optional[str]:
        val = self.port_combo.get()
        if not val or "未检测到" in val:
            return None
        return val.split(" - ")[0].strip()

    # ============================================================
    # 烧录与擦除
    # ============================================================

    def _start_flash(self):
        if self._is_flashing:
            messagebox.showwarning("提示", "正在执行操作，请稍候...")
            return

        port = self._get_selected_port()
        if not port:
            messagebox.showerror("错误", "请先选择一个有效的串口！")
            return

        baud = int(self.baud_combo.get() or "921600")

        self._set_busy(True, "正在烧录...")
        self.status_var.set(f"正在烧录至 {port}...")

        def _on_done(success: bool, err: Optional[str]):
            self.after(0, self._on_flash_completed, success, err)

        try:
            self.flasher.flash(port=port, baud=baud, background=True, on_done=_on_done)
        except Exception as e:
            self._set_busy(False)
            messagebox.showerror("错误", str(e))

    def _on_flash_completed(self, success: bool, err: Optional[str]):
        self._set_busy(False)
        if success:
            self.status_var.set("烧录成功！")
            messagebox.showinfo(
                "烧录成功",
                "🎉 固件烧录成功！\n\n设备正在自动重启进入正常运行模式。\n现在你可以打开浏览器访问 http://192.168.7.1 进行体验！"
            )
        else:
            self.status_var.set("烧录失败")
            messagebox.showerror("烧录失败", f"烧录过程中出现错误：\n\n{err or '未知错误'}")

    def _start_erase(self):
        if self._is_flashing:
            return

        port = self._get_selected_port()
        if not port:
            messagebox.showerror("错误", "请先选择串口！")
            return

        if not messagebox.askyesno(
            "高危警告",
            "全片擦除将彻底清空 ESP32-S3 Flash 上的所有数据（包括密码库与固件）！\n\n擦除后设备将无法开机，直到重新烧录固件。\n确定要继续擦除吗？"
        ):
            return

        baud = int(self.baud_combo.get() or "921600")
        self._set_busy(True, "正在擦除 Flash...")
        self.status_var.set("正在擦除整块 Flash...")

        def _on_done(success: bool, err: Optional[str]):
            self.after(0, self._on_erase_completed, success, err)

        try:
            self.flasher.erase_flash(port=port, baud=baud, background=True, on_done=_on_done)
        except Exception as e:
            self._set_busy(False)
            messagebox.showerror("错误", str(e))

    def _on_erase_completed(self, success: bool, err: Optional[str]):
        self._set_busy(False)
        if success:
            self.status_var.set("擦除完成！")
            messagebox.showinfo("擦除完成", "Flash 已经全部擦除完毕！请点击【开始烧录固件】重新刷入固件。")
        else:
            self.status_var.set("擦除失败")
            messagebox.showerror("擦除失败", f"擦除失败：\n\n{err}")

    def _set_busy(self, busy: bool, text: str = ""):
        self._is_flashing = busy
        st = tk.DISABLED if busy else tk.NORMAL
        self.flash_btn.configure(state=st)
        self.erase_btn.configure(state=st)
        self.monitor_btn.configure(state=st)
        if busy:
            self.flash_btn.configure(text=f"⏳ {text}")
        else:
            self.flash_btn.configure(text="⚡ 开始烧录固件")

    def _install_esptool(self):
        self.install_btn.configure(state=tk.DISABLED, text="安装中...")
        self.status_var.set("正在安装 esptool...")

        def _worker():
            ok = self.flasher.install_esptool()
            self.after(0, self._on_install_done, ok)

        threading.Thread(target=_worker, daemon=True).start()

    def _on_install_done(self, ok: bool):
        self.install_btn.configure(text="📦 安装 esptool")
        if ok:
            self.status_var.set("esptool 安装成功")
            self.install_btn.configure(state=tk.DISABLED)
            messagebox.showinfo("成功", "esptool 与 pyserial 安装成功！")
        else:
            self.status_var.set("安装失败")
            self.install_btn.configure(state=tk.NORMAL)
            messagebox.showerror("失败", "esptool 安装失败，请检查网络连接或手动运行 pip install esptool。")

    def _open_monitor(self):
        port = self._get_selected_port()
        if not port:
            messagebox.showwarning("提示", "请先选择一个串口！")
            return
        baud = int(self.baud_combo.get() or "115200")
        MonitorWindow(self, port, baud)


class MonitorWindow(tk.Toplevel):
    """独立串口监视器窗口"""
    def __init__(self, parent, port: str, baud: int):
        super().__init__(parent)
        self.title(f"串口监视器 - {port} @ {baud}")
        self.geometry("700x450")

        self.port = port
        self.baud = baud
        self.serial = None
        self.running = False

        frame = ttk.Frame(self, padding=8)
        frame.pack(fill=tk.BOTH, expand=True)

        toolbar = ttk.Frame(frame)
        toolbar.pack(fill=tk.X, pady=(0, 6))

        ttk.Label(toolbar, text=f"设备: {port}").pack(side=tk.LEFT, padx=(0, 10))
        self.status_lbl = ttk.Label(toolbar, text="正在连接...", foreground="#f39c12")
        self.status_lbl.pack(side=tk.LEFT)

        ttk.Button(toolbar, text="清屏", command=self._clear, width=6).pack(side=tk.RIGHT)

        self.text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, font=("Consolas", 9), bg="#1e272e", fg="#d2dae2")
        self.text.pack(fill=tk.BOTH, expand=True)

        self._connect()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _clear(self):
        self.text.delete("1.0", tk.END)

    def _connect(self):
        try:
            import serial
            self.serial = serial.Serial(self.port, self.baud, timeout=0.1)
            self.running = True
            self.status_lbl.configure(text="● 已连接", foreground="#2ecc71")
            threading.Thread(target=self._read_loop, daemon=True).start()
        except Exception as e:
            self.status_lbl.configure(text=f"连接失败: {e}", foreground="#e74c3c")

    def _read_loop(self):
        while self.running and self.serial and self.serial.is_open:
            try:
                if self.serial.in_waiting:
                    data = self.serial.read(self.serial.in_waiting)
                    try:
                        text = data.decode("utf-8", errors="replace")
                        self.after(0, self._append_text, text)
                    except Exception:
                        pass
            except Exception:
                break
            time.sleep(0.01)

    def _append_text(self, text: str):
        self.text.insert(tk.END, text)
        self.text.see(tk.END)

    def _on_close(self):
        self.running = False
        if self.serial and self.serial.is_open:
            try:
                self.serial.close()
            except Exception:
                pass
        self.destroy()


def main():
    app = KEYVAULTFlashGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
