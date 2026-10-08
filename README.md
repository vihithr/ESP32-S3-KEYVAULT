# 🔐 KeyVault USB —— ESP32-S3 离线硬件级高密密钥管理设备

KeyVault 是一款基于 ESP32-S3 原生 USB-OTG 打造的**完全离线、高冗余、高安全密码与密钥保险箱**。
设备仅需单根 Type-C 数据线插入 PC、Mac 或手机，即可自动建立点对点高速虚拟网络，通过现代 Web 界面管理账户凭证、SSH 密钥、API Token、加密笔记等机密资产。

---

## 🌟 核心特性与架构亮点

### 1. 🗄️ 超大存储容量（1,536 条独立加密资产）
- **容量升级**：支持 **1,024 条账号凭证** + **512 条自由 KV 存储**（总计 1,536 条机密记录）。
- **分区配置**：双区各配置 **512KB**（总计 1MB 冗余池），轻松容纳万次擦写与日志式动态磨损均衡。

### 2. 🗜️ 独创确定性两级无损压缩（TLV + 7-bit 位打包）
- **紧凑 TLV 二进制布局**：彻底剥离 JSON 冗余键名（`name`, `user`, `pass` 等），大幅削减存储开销。
- **7-bit ASCII 位流紧密打包**：针对英文字符、数字和常见密码符号（ASCII 0x20~0x7E），将每 8 个 7-bit 字符压缩至 7 个物理字节，空间占用立减 **12.5%**。
- **Compress-then-Encrypt（免侧信道）**：压缩在内存隔离区严格于加密前完成，密文长度与明文字符数呈固定确定性线性比例，彻底免疫 CRIME / BREACH 类型的长度泄露侧信道攻击。
- **向下无缝兼容**：自动识别旧版 JSON 密文并平滑解码，写入时自动升级为 TLV 紧凑格式。

### 3. 🛡️ 双区冗余镜像与闪存健康自愈监控
- **双区独立写入（Active-Mirror Dual Zones）**：`vault` (0xD000) 与 `vault2` (0x8D000) 互为热备份，每条数据拥有独立的 12 字节 Nonce、AES-GCM 认证 Tag 与 CRC32 完整性校验。
- **单粒子翻转 / 掉电交叉自愈**：读取时若检测到任一分区 CRC 损坏或校验失败，系统自动从镜像分区提取正确数据并对损坏分区实施**即时透明静默修复（Self-Healing）**。
- **累计写入统计与寿命保护**：实时监测 NVS 累计写入次数、槽位使用率与自愈次数。若极端情况下双区均故障，设备立即触发**安全降级只读保护（Safe Read-Only Mode）**，锁死写入、开放导出，确保资产永不丢失。

### 4. 🔒 全链路端到端加密（HTTP Zero-Config E2EE）
- **无证书红屏痛点解决**：免除局域网私有 CA 导入与 HTTPS 不安全警告（针对 `192.168.7.1` 等非 localhost 私网 IP）。
- **纯原生 JS 密码学引擎**：前端内嵌纯原生 JavaScript 实现的 **RFC 7748 X25519 (ECDH)**、**SHA-256** 与 **AES-256-GCM (带 GHASH 认证)**，完全不依赖受限的 `window.crypto.subtle` 安全上下文，全平台各端浏览器即插即用。
- **瞬态密钥协商（Ephemeral Key Exchange）**：每次会话建立时，客户端与 ESP32-S3 分别生成一次性 X25519 密钥对，派生独立的 256 位会话密钥，所有 HTTP 请求载荷与响应全部经硬件加速 AES-256-GCM 密文封包传输。任何局域网抓包或恶意嗅探仅能捕获高熵密文，无法窃听主密码、Token 或凭证。

### 5. 🔌 纯单一 RNDIS 虚拟网卡与零射频安全
- **单 RNDIS 专属驱动模式**：杜绝多网卡共存引发的 IP 路由争抢与主机绑定冲突，即插即用自动通过内置 DHCP Server 获取 `192.168.7.2`。
- **默认零射频**：固件默认不启动 Wi-Fi 与蓝牙，无任何无线电磁辐射暴露。
- **物理按键授权**：关键安全操作（初次初始化、登录解锁）必须按下 ESP32-S3 板载 **BOOT** 实体按键授权，阻断远程自动化撞库与恶意注入。

---

## 📐 硬件与启动模式

ESP32-S3 内部的 USB-Serial/JTAG 与 USB-OTG 共用物理管脚（`GPIO19: D-`, `GPIO20: D+`）。本工程通过软件状态机实现全自动平滑管理：

1. **默认模式（USB 离线网卡模式）**：
   - 上电开机经历 3 秒缓冲倒计时后，直接进入 USB 虚拟网卡模式，浏览器直达：`http://192.168.7.1`。
2. **调试 / 烧录保护模式**：
   - 在开机 3 秒倒计时内**短按板载 BOOT 键（GPIO0）**，设备永久停留在 USB-Serial/JTAG 串口，LED 闪烁，便于 PlatformIO 烧录固件或调试日志。
3. **应急 Wi-Fi 救援模式**：
   - 任意时刻**长按板载 BOOT 键 10 秒**（或开机瞬间按住 BOOT 键），设备启动应急无线救援热点（SSID: `KeyVault-Recovery`，密码: `vault2024`，访问 `http://192.168.4.1`）。

---

## 🚀 快速开始与一键烧录

### 方式一：使用一键自动化脚本（推荐）
在 Windows PowerShell 下直接运行仓库根目录的烧录工具：
```powershell
.\flash.ps1
```
脚本将自动扫描连接端口、上传分区表与固件、并校验网络连通性。

### 方式二：PlatformIO 标准构建
```powershell
# 1. 编译固件与网页资源
pio run

# 2. 烧录固件到开发板
pio run -t upload

# 3. 查看实时调试串口
pio device monitor
```

---

## 🗃️ 闪存分区结构表 (4MB Flash)

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
| **GET** | `/api/status` | 查询设备初始化与连接状态 | 免认证 |
| **POST** | `/api/e2ee/handshake` | 协商 Ephemeral X25519 会话密钥 | 免认证 |
| **GET** | `/api/health` | 查询双区健康度、自愈修复次数与写入统计 | 免认证 |
| **GET** | `/api/usb` | 查询 USB 网卡协议与分配 IP | 免认证 |
| **POST** | `/api/setup` | 首次配置主密码（需物理按键确认） | 免认证 |
| **POST** | `/api/login` | 输入主密码解锁（需物理按键确认） | 免认证 |
| **POST** | `/api/lock` | 紧急上锁并即时销毁会话密钥 | 免认证（安全兜底） |
| **GET** | `/api/creds` | 获取所有凭证摘要列表 | `X-Token` |
| **POST** | `/api/creds` | 新增凭证 | `X-Token` |
| **GET** | `/api/cred/<id>` | 获取指定凭证的明文密码 | `X-Token` |
| **POST** | `/api/cred/update` | 更新指定凭证 | `X-Token` |
| **POST** | `/api/cred/delete` | 删除凭证 | `X-Token` |
| **GET** | `/api/kv` | 获取所有自定义 KV 键名列表 | `X-Token` |
| **POST** | `/api/kv` | 写入或更新自定义 KV | `X-Token` |
| **GET** | `/api/kv/<key>` | 获取指定 KV 的完整内容 | `X-Token` |
| **POST** | `/api/kv/delete` | 删除指定 KV | `X-Token` |
| **POST** | `/api/generate` | 高强度物理硬件真随机数密码生成 | 免认证 |
| **POST** | `/api/chpwd` | 修改主密码并批量全库重加密 | `X-Token` |
| **POST** | `/api/export` | 导出 AES 全量密文备份（`.kvbk`） | `X-Token` |
| **POST** | `/api/import` | 导入全量密文备份并覆盖恢复 | `X-Token` |
| **POST** | `/api/reset` | 物理格式化并重置全部机密数据 | `X-Token` |
| **POST** | `/api/reboot` | 重启设备 | `X-Token` |

> **提示**：所有 API 请求若携带 `X-E2EE-Session` 请求头，均由前后端引擎透明完成 AES-256-GCM 加密封装与解密。

---

## 📁 项目目录结构

```
ESP32-S3-KEYVAULT/
├── partitions.csv            # 512KB 双区高冗余分区表
├── platformio.ini            # PlatformIO 构建配置
├── flash.ps1                 # 一键智能烧录与调试脚本
├── LICENSE                   # MIT 开源协议
├── tools/
│   └── gen_web_content.py    # 网页单次无损 C 转义生成工具
└── src/
    ├── main.c                # 核心事件循环、HTTP 路由编排与 E2EE 拦截
    ├── keyvault.h / c        # 1536 条容量管理、7-bit 压缩、双区自愈与健康监控
    ├── e2ee.h / c            # RFC 7748 X25519、硬件 AES-256-GCM 密码学服务
    ├── rndis.h / c           # 纯 RNDIS 虚拟以太网 TinyUSB 类驱动
    ├── usb_net.h / c         # 网络适配层、DHCP Server 与 IP 栈管理
    ├── usb_desc.h / c        # USB 硬件设备与配置描述符
    ├── json_util.h / c       # 高效轻量 JSON 字符串转义与字段解析器
    ├── web_content.h / c     # 嵌入式 Web 前端只读资源
    └── index.html            # 现代化暗色风格响应式 Web UI（内嵌纯 JS 密码引擎）
```

---

## 📜 开源协议

本项目采用 [MIT 许可证](LICENSE) 开源。欢迎自由使用、审计与二次开发！
