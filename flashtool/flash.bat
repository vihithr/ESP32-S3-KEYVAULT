@echo off
chcp 65001 >nul
title KEYVAULT-ESP32 命令行固件烧录工具
color 0F

echo ========================================================
echo   KEYVAULT-ESP32 一键固件烧录工具 (v1.1.0)
echo ========================================================
echo.

set "PY_CMD="

REM 1. 检查已激活的 Conda
if defined CONDA_PREFIX (
    if exist "%CONDA_PREFIX%\python.exe" (
        set "PY_CMD=%CONDA_PREFIX%\python.exe"
        goto FOUND_PY
    )
)

REM 2. 检查已激活的 venv
if defined VIRTUAL_ENV (
    if exist "%VIRTUAL_ENV%\Scripts\python.exe" (
        set "PY_CMD=%VIRTUAL_ENV%\Scripts\python.exe"
        goto FOUND_PY
    )
)

REM 3. 检查本地 .venv
if exist "%~dp0.venv\Scripts\python.exe" (
    set "PY_CMD=%~dp0.venv\Scripts\python.exe"
    goto FOUND_PY
)
if exist "%~dp0..\.venv\Scripts\python.exe" (
    set "PY_CMD=%~dp0..\.venv\Scripts\python.exe"
    goto FOUND_PY
)

REM 4. 检查 PlatformIO 运行环境
if exist "%USERPROFILE%\.platformio\penv\Scripts\python.exe" (
    set "PY_CMD=%USERPROFILE%\.platformio\penv\Scripts\python.exe"
    goto FOUND_PY
)

REM 5. 检查系统全局 python
python --version >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    set "PY_CMD=python"
    goto FOUND_PY
)

echo [错误] 未检测到可用的 Python/Conda/venv 环境！
pause
exit /b 1

:FOUND_PY
echo [环境] 使用 Python: %PY_CMD%
echo.

REM 列出可用串口
echo [检测] 当前可用串口列表:
"%PY_CMD%" -c "import serial.tools.list_ports; [print(f'   {p.device} - {p.description}') for p in serial.tools.list_ports.comports()]" 2>nul || echo   (未安装 pyserial，无法自动列出)
echo.

set /p COMPORT="请输入串口号 (例如 COM3, 直接回车默认为 COM3): "
if "%COMPORT%"=="" set COMPORT=COM3

echo.
echo 正在准备通过 %COMPORT% 烧录 ESP32-S3 固件...
echo.

"%PY_CMD%" -m esptool --chip esp32s3 -p %COMPORT% -b 921600 --before default_reset --after hard_reset write_flash --flash_mode dio --flash_size 4MB --flash_freq 80m 0x0 "%~dp0firmware\bootloader.bin" 0x8000 "%~dp0firmware\partitions.bin" 0x10000 "%~dp0firmware\firmware.bin"

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================================
    echo   [SUCCESS] 固件烧录成功！ESP32-S3 已自动复位启动。
    echo   请在浏览器打开: http://192.168.7.1
    echo ========================================================
) else (
    echo.
    echo ========================================================
    echo   [ERROR] 烧录失败！
    echo   提示: 若连接超时，请按住板载 [BOOT] 键，按一下 [RST] 键松开。
    echo ========================================================
)

echo.
pause
