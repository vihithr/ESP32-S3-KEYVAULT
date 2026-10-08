# 🔐 KEYVAULT-ESP32 —— 基于 ESP32 的离线硬件密钥与凭证管理设备

[English](README_EN.md) | [中文](README.md)

**KEYVAULT-ESP32** 是一款基于 ESP32-S3 原生 USB-OTG 打造的**离线硬件密码与机密凭证管理设备**。

设备通过标准 Type-C 数据线连接至 PC、Mac、Linux 或移动设备，利用内置的 USB 虚拟网卡（RNDIS）和 USB HID 键盘协议，让用户在免装驱动、免装独立客户端的前提下，直接在现代浏览器中管理账户凭证、API Token、SSH 密钥和私密笔记，并支持通过物理按键安全模拟键盘直接输入。

---

## 🛠️ 核心功能与安全设计

### 1. 🗄️ 凭证存储与容量规划
- **多槽位容量**：支持存储 **1,024 条账户凭证** + **512 条自定义键值对 (KV)**（共 1,536 个独立条目）。
- **分区配置**：双区各分配 512KB Flash 空间（共 1MB 存储池），支持日志式磨损均衡，减少局部 Flash 损耗。

### 2. 🗜️ 数据编码与紧凑存储
- **紧凑 TLV 布局**：采用 TLV（Type-Length-Value）二进制结构代替冗余的 JSON 文本键名，减少存储开销。
- **7-bit ASCII 位流打包**：针对英文字符、数字及常见密码符号（ASCII `0x20` ~ `0x7E`），将每 8 个 7-bit 字符压缩至 7 个字节存储，进一步提升存储利用率。
- **压缩后加密 (Compress-then-Encrypt)**：压缩过程在内存独立缓冲区中且在加密之前完成，定长与确定性填充设计有助于降低长度泄露风险。
- **格式平滑迁移**：自动兼容旧版数据，并在下次写入时平滑转为紧凑格式。

### 3. 🛡️ 双区镜像与存储完整性校验
- **双区独立镜像备份**：划分 `vault` 与 `vault2` 两个独立 NVS 分区互为镜像；每条记录均附带独立的 Nonce、AES-GCM 认证 Tag 与 CRC32 校验码。
- **校验与自愈恢复**：读取时若检测到单侧分区数据损坏或校验异常，系统自动尝试从镜像分区读取并回写修复损坏区域。
- **写入寿命监测与降级保护**：跟踪 Flash 累计擦写次数、槽位占用率与自愈统计；若遇到极端损坏导致双区均不可靠，设备将自动进入**只读保护模式**，禁止写入但允许导出备份。

### 4. 🔒 应用层端到端加密传输 (E2EE)
- **免证书警告**：解决内网私有 IP（如 `192.168.7.1`）在现代浏览器中因无公信 CA 证书而出现的警告问题。
- **原生 JS 密码学套件**：前端采用原生 JavaScript 实现的 **RFC 7748 X25519 (ECDH)**、**SHA-256** 与 **AES-256-GCM**，不依赖非安全上下文受限的 Web Crypto API，保证主流浏览器兼容性。
- **前向安全临时会话**：每次会话建立时，客户端与硬件各自生成临时的 X25519 密钥对，协商出独立的 256 位会话密钥。所有 HTTP 交互载荷均在应用层完成 AES-GCM 加密与验签，传输链路不暴露明文凭证。

### 5. ⌨️ USB HID 硬件模拟键入 (Auto-Type)
- **复合设备免驱设计**：在 RNDIS 虚拟网卡基础上扩展标准 USB HID 键盘接口，主流操作系统即插即用。
- **30 秒单次武装状态机**：在 Web 界面选择条目点击武装后，凭证解密并临时暂存于 RAM，启动 30 秒超时倒计时。
- **物理按键触发击键**：将输入光标移至目标输入框（锁屏、终端命令行、登录界面等），轻按一次板载 **BOOT** 键，单片机模拟键盘物理击键逐字输入。
- **安全约束与擦除**：
  - **不输出 Enter 键**：输入完成后停在密码末尾，避免第三方表单提前误提交。
  - **规避剪贴板风险**：全程不向操作系统剪贴板写入任何内容，降低恶意软件监听剪贴板的风险。
  - **及时物理擦除**：击键完成或武装超时后，立即调用 `vault_secure_zero` 清空易失性内存中的明文缓存。

### 6. 🔘 物理按键确认 (2FA) 与离线特性
- **查看密码物理授权**：在网页端点击查看或复制密码明文时，设备进入 15 秒物理等待状态，**必须现场按下板载 BOOT 键确认后才返回明文**，避免后台未经授权的静默抓取。
- **默认无无线射频**：固件默认不启用 Wi-Fi 和蓝牙，减少无线侧潜在的攻击面。
- **主密码原文不落盘**：Flash 中仅存储盐值与哈希验证值；校验过程在 RAM 中完成，校验后立即擦除相关内存缓冲区。

---

## 🛡️ 威胁模型与安全边界 (Threat Model)

任何实用的安全系统都必须建立在清晰的威胁假设之上。KEYVAULT-ESP32 的核心防御目标是：**在有限成本与便捷便携的前提下，防范日常计算机环境中绝大多数自动化网络攻击与木马恶意软件，将“全库陷落”风险收敛为不可行**。

### 1. 本方案有效防御的攻击场景 (In-Scope)
- **后台自动化脚本 / 恶意软件批量拖库**：
  即便宿主机被注入后台恶意进程，由于所有凭证解密与查看均被单片机硬件挂起并强制要求物理按下板载按键，恶意程序无法在缺乏现场人类物理干预的情况下静默窃取整个密钥库。
- **系统剪贴板监听器与劫持木马 (Clipboard Hijacking)**：
  借助 USB HID 硬件逐字模拟击键（Auto-Type），凭证直接注入活动光标窗口，彻底绕过宿主机操作系统的剪贴板通道，杜绝基于剪贴板钩子的被动监听。
- **网络层明文嗅探与未经授权的链路交互**：
  基于应用层 X25519 临时密钥协商与 AES-256-GCM 封装，USB 虚拟网络线路上全程传输高熵密文，不暴露明文凭证。
- **非交互式在线爆破**：
  登录验证同样需要物理按键放行，在线自动化字典穷举连首次请求都无法完成。

### 2. 密码学权衡：PBKDF2 迭代与密码熵 (KDF vs Entropy)
- **关于 30,000 次 PBKDF2 的工程取舍**：
  在主频 240MHz 的 ESP32-S3 上，30k 次迭代约耗时 80~150ms，可在避免触发 FreeRTOS 任务看门狗（WDT）的同时保障即开即用的流畅体验。
- **线性延迟 vs 指数级搜索空间**：
  KDF 迭代次数提供的是**线性阻滞系数**，而**主密码本身的熵值（长度与字符集）提供的是指数级的鸿沟**。例如 12 位以上的高熵密码搜索空间高达 $10^{22}$ 数量级，配合 30k 迭代足以在数学上使离线暴力破解变得不切实际。
- **离线破解的前提门槛**：
  离线暴力破解成立的前提极为严苛：攻击者必须物理窃取硬件实体、具备拆焊或硬件导出 Flash 镜像的能力、并逆向私有存储布局；此外，若启用 ESP32-S3 原生硬件 **Flash Encryption (AES-XTS) 与 eFuse 物理熔断**，即使剥离 Flash 颗粒读取出来的也是高熵随机白噪声。

### 3. 明确的安全边界与非目标 (Out-of-Scope / Non-Goals)
软件和单片机固件无法解决超出其物理与逻辑边界的问题，以下场景属于本系统的明确非目标：
- **终端完全失陷 (Compromised Endpoint)**：
  若宿主机已被内核级 Rootkit、驱动级按键记录器接管，硬件虽然能保护密码库不被整体 dump，但无法阻止当前单次击键输入的凭证在操作系统内部被记录（此类场景需依赖 FIDO2 / Passkey 等公钥签名机制）。
- **网络钓鱼 (Phishing Attacks)**：
  用户若主动将凭证注入伪造的李鬼站点，由于传统密码缺乏域名强绑定特性（Origin-Bound），硬件无法判断目标站点的真实性。
- **现实世界人身逼供与社交工程 (Physical Coercion / OPSEC)**：
  面对现实世界中的主密钥窥探、密码泄露或物理强迫（即“5美元扳手攻击”），属于操作安全（OPSEC）与人身安全范畴。
- **实验室级硬件芯片逆向 (Lab-Grade Physical Attacks)**：
  如聚焦离子束 (FIB)、差分功耗分析 (DPA)、激光故障注入等芯片级硬件攻击，需依赖带有硬件物理防篡改网格的专用安全元件 (Secure Element, 如 ATECC608A)。

---

## 📐 硬件与启动模式

ESP32-S3 的 USB-Serial/JTAG 与 USB-OTG 共用物理引脚（`GPIO19: D-`, `GPIO20: D+`）。本工程通过软件状态机管理模式切换：

1. **默认模式（USB 离线网卡模式）**：
   - 设备上电后经历 3 秒缓冲倒计时，自动进入 USB 虚拟网卡模式，在浏览器访问：`http://192.168.7.1`。
2. **固件烧录 / 串口调试模式**：
   - 在开机 3 秒倒计时内**短按板载 BOOT 键（GPIO0）**，设备保持在 USB-Serial/JTAG 串口模式，LED 闪烁，便于 PlatformIO 烧录固件或查看串口日志。
3. **应急 Wi-Fi 模式**：
   - 在运行中**长按板载 BOOT 键 10 秒**（或开机瞬间长按 BOOT），设备将启动应急临时热点（SSID: `KeyVault-Recovery`，密码: `vault2024`，访问 `http://192.168.4.1`）。

---

## 🚀 快速开始与固件烧录

### 方式一：下载 Release 预编译包烧录（推荐）
在 GitHub Releases 下载预编译发布包 `ESP32-S3-KEYVAULT-vX.X.X-release.zip` 并解压：
- **🖥️ 图形化烧录工具（推荐）**：双击运行 `flash_gui.bat`，可自动检测系统 Python/Conda/venv 环境、自动扫描 ESP32-S3 串口，提供一键烧录、全片擦除与串口日志监视器。
- **⌨️ 命令行极简烧录**：双击运行 `flash.bat`，输入串口号（如 COM3）即可一键刷入。

### 方式二：源码编译构建 (PlatformIO)
```powershell
# 1. 编译嵌入式网页与固件
python tools/gen_web_content.py
pio run

# 2. 烧录固件到开发板
pio run -t upload

# 3. 查看运行日志
pio device monitor
```

### 方式三：esptool 命令行烧录
```bash
esptool.py --chip esp32s3 -p <COM_PORT> -b 921600 write_flash \
  0x0 flashtool/firmware/bootloader.bin \
  0x8000 flashtool/firmware/partitions.bin \
  0x10000 flashtool/firmware/firmware.bin
```

---

## 🗃️ 闪存分区结构 (4MB Flash)

```csv
# Name,   Type, SubType, Offset,   Size,     Flags
nvs,      data, nvs,     0x9000,   0x4000,
vault,    data, nvs,     0xD000,   0x80000,  # 512KB 主分区 (1024 Creds + 512 KV)
vault2,   data, nvs,     0x8D000,  0x80000,  # 512KB 冗余备份镜像分区
factory,  app,  factory, 0x110000, 0x1D0000, # 1.81MB 固件程序区 (64KB 对齐)
```

---

## 🌐 API 接口概览

| 方法 | 路径 | 功能说明 | 认证方式 |
| :--- | :--- | :--- | :--- |
| **GET** | `/api/status` | 查询设备状态与初始化标记 | 免认证 |
| **POST** | `/api/e2ee/handshake` | 协商临时 X25519 会话密钥 | 免认证 |
| **GET** | `/api/health` | 查询双区健康状态与写入统计 | 免认证 |
| **GET** | `/api/usb` | 查询 USB 网卡状态与 IP 信息 | 免认证 |
| **POST** | `/api/setup` | 初始化主密码（需板载按键确认） | 免认证 |
| **POST** | `/api/login` | 登录验证主密码（需板载按键确认） | 免认证 |
| **POST** | `/api/lock` | 锁定并销毁内存中的会话密钥 | 免认证 |
| **GET** | `/api/creds` | 获取凭证摘要列表 | `X-Token` |
| **POST** | `/api/creds` | 添加凭证条目 | `X-Token` |
| **GET** | `/api/cred/<id>` | 获取凭证详情（需板载按键确认） | `X-Token` |
| **POST** | `/api/cred/update` | 更新凭证内容 | `X-Token` |
| **POST** | `/api/cred/delete` | 删除凭证条目 | `X-Token` |
| **GET** | `/api/kv` | 获取自定义键名列表 | `X-Token` |
| **POST** | `/api/kv` | 写入或更新自定义键值对 | `X-Token` |
| **GET** | `/api/kv/<key>` | 读取键值详情（需板载按键确认） | `X-Token` |
| **POST** | `/api/kv/delete` | 删除指定键值对 | `X-Token` |
| **POST** | `/api/hid/arm` | 单次武装凭证用于 HID 模拟键入 | `X-Token` |
| **POST** | `/api/hid/disarm` | 取消 HID 武装状态并抹除缓存 | `X-Token` |
| **GET** | `/api/hid/status` | 查询当前 HID 武装状态与剩余有效时间 | `X-Token` |
| **POST** | `/api/generate` | 生成硬件真随机数安全密码 | 免认证 |
| **POST** | `/api/chpwd` | 修改主密码并执行数据全量重加密 | `X-Token` |
| **POST** | `/api/export` | 导出加密备份文件 (`.kvbk`) | `X-Token` |
| **POST** | `/api/import` | 导入并恢复加密备份 | `X-Token` |
| **POST** | `/api/reset` | 抹除数据并恢复出厂状态 | `X-Token` |
| **POST** | `/api/reboot` | 重启硬件设备 | `X-Token` |

> 所有支持 E2EE 的 API 请求若携带 `X-E2EE-Session` 请求头，数据载荷将通过 AES-256-GCM 密文封包传输。

---

## 📁 项目目录结构

```
KEYVAULT-ESP32/
├── partitions.csv            # 512KB 双区冗余分区表
├── platformio.ini            # PlatformIO 构建配置文件
├── flash.ps1                 # 辅助烧录脚本
├── LICENSE                   # MIT 开源许可证
├── README.md                 # 中文技术说明
├── README_EN.md              # 英文技术说明
├── flashtool/                # 预编译固件与图形化烧录工具包
│   ├── esp32_flash_gui.py    # GUI 烧录器 (串口检测 / 烧录 / 擦除 / 监视器)
│   ├── esp32_flasher.py      # 烧录底层引擎 (支持 Conda / venv / 系统 Python)
│   ├── flash_gui.bat         # 双击启动图形界面 (智能环境自适应)
│   ├── flash.bat             # 命令行极简烧录批处理
│   ├── create_package.py     # 自动化编译、同步与发布包打包脚本
│   ├── requirements.txt      # 烧录依赖 (esptool, pyserial)
│   └── firmware/             # 预编译二进制固件 (bootloader/partitions/firmware)
├── tools/
│   └── gen_web_content.py    # 网页文件转换为 C 源码工具
└── src/
    ├── main.c                # 主循环、HTTP 路由处理与事件协调
    ├── keyvault.h / c        # 1536 条容量管理、7-bit 编码、双区镜像与自愈
    ├── e2ee.h / c            # X25519 密钥协商与 AES-256-GCM 编解码
    ├── usb_hid.h / c         # USB HID 键盘模拟与单次武装状态机
    ├── rndis.h / c           # RNDIS 虚拟网卡类驱动
    ├── usb_net.h / c         # 网络适配、DHCP 服务与 IP 栈管理
    ├── usb_desc.h / c        # USB 复合设备描述符与端点分配
    ├── json_util.h / c       # 轻量 JSON 字段解析器
    ├── web_content.h / c     # 嵌入式 Web 静态资源
    └── index.html            # 响应式 Web 界面（支持中英双语与纯 JS 密码引擎）
```

---

## 📜 开源协议

本项目基于 [MIT 许可证](LICENSE) 开源。
