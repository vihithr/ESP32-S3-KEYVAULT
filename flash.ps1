# KeyVault 智能烧录与监控脚本
# 自动检测端口 -> 上传固件 -> 启动串口监视器

$pio = "C:\Users\vihi\.platformio\penv\Scripts\pio.exe"
if (-not (Test-Path $pio)) {
    $pio = "pio"
}

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "   🔐 KeyVault ESP32-S3 一键烧录与调试脚本" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# 1. 查找端口
Write-Host "[1/3] 正在扫描 ESP32 烧录端口..." -ForegroundColor Yellow
$foundPort = $null

for ($i = 0; $i -lt 60; $i++) {
    $ports = Get-CimInstance Win32_PnPEntity | Where-Object { 
        ($_.PNPClass -eq "Ports" -or $_.ClassGuid -eq "{4d36e978-e325-11ce-bfc1-08002be10318}") -and 
        $_.DeviceID -like "*VID_303A*"
    }

    if ($ports) {
        $p = $ports | Select-Object -First 1
        Write-Host "  -> 发现可用端口: $($p.Name)" -ForegroundColor Green
        $foundPort = $p
        break
    }
    
    if ($i -eq 1) {
        Write-Host "  [提示] 请按住板载 [BOOT] 键不放，点按一下 [RESET] 键，然后松开 [BOOT] 进入 ROM 烧录模式..." -ForegroundColor Cyan
    }
    Start-Sleep -Milliseconds 800
}

# 2. 烧录
if (-not $foundPort) {
    Write-Host "`n⚠️ 未能在限定时间内检测到 ESP32 烧录端口！" -ForegroundColor Red
    Write-Host "操作方法：按住板载 [BOOT] 键不要松开，点按一下 [RESET] 键，然后松开 [BOOT] 键进入 ROM 下载模式，再运行本脚本。" -ForegroundColor Yellow
    exit 1
}

Write-Host "`n[2/3] 开始烧录固件到 ESP32-S3..." -ForegroundColor Yellow
if ($foundPort.Name -match "(COM\d+)") {
    $portName = $matches[1]
    Write-Host "  -> 指定烧录端口: $portName" -ForegroundColor Cyan
    & $pio run -t upload --upload-port $portName
} else {
    & $pio run -t upload
}

if ($LASTEXITCODE -ne 0) {
    Write-Host "`n❌ 烧录失败 (退出码: $LASTEXITCODE)" -ForegroundColor Red
    Write-Host "排查指引：" -ForegroundColor Yellow
    Write-Host " 1. 确保使用具有数据传输功能的 Type-C 数据线（非纯充电线）"
    Write-Host " 2. 尝试按住 BOOT 键，按一下 RESET 键，再重新运行此脚本"
    exit $LASTEXITCODE
}

Write-Host "`n✅ 固件烧录成功！" -ForegroundColor Green

# 3. 提示与检测 USB 网卡状态
Write-Host "`n[3/3] 开发板已冷启动直入 USB 原生网卡模式！" -ForegroundColor Cyan
Write-Host "  -> 电脑正在自动枚举 USB 网卡并分配 IP (192.168.7.2)..." -ForegroundColor Yellow
Write-Host "  -> 管理地址: http://192.168.7.1" -ForegroundColor Green
Write-Host "  -> 提示: 任意时刻长按开发板 [BOOT] 键 10 秒可激活应急 Wi-Fi (KeyVault-Recovery -> 192.168.4.1)" -ForegroundColor DarkCyan
Write-Host "--------------------------------------------------" -ForegroundColor DarkGray
Start-Sleep -Seconds 3

Write-Host "正在检测设备网络连通性 (Ping 192.168.7.1)..." -ForegroundColor Yellow
$pingOk = Test-Connection -TargetName "192.168.7.1" -Count 2 -Quiet -ErrorAction SilentlyContinue
if ($pingOk) {
    Write-Host "🎉 成功连通 KeyVault (192.168.7.1)！请直接在浏览器打开: http://192.168.7.1" -ForegroundColor Green
} else {
    Write-Host "💡 提示：若 192.168.7.1 暂未响应（可能受代理软件或网卡初次加载影响）：" -ForegroundColor Yellow
    Write-Host "   1. 检查电脑网络适配器中是否有新出现的以太网卡"
    Write-Host "   2. 或者长按开发板 [BOOT] 键 10 秒开启无线热点 KeyVault-Recovery (访问 http://192.168.4.1)"
}
