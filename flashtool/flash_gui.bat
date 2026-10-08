@echo off
chcp 65001 >nul
title KEYVAULT-ESP32 固件烧录工具
color 0F

echo ========================================================
echo   KEYVAULT-ESP32 固件烧录工具 (图形界面)
echo ========================================================
echo.

set "PY_CMD="

REM 1. 检查当前是否在已激活的 Conda 环境
if defined CONDA_PREFIX (
    if exist "%CONDA_PREFIX%\python.exe" (
        set "PY_CMD=%CONDA_PREFIX%\python.exe"
        echo [环境] 检测到已激活的 Conda 环境: %CONDA_PREFIX%
        goto FOUND_PY
    )
)

REM 2. 检查当前是否在已激活的 venv 环境
if defined VIRTUAL_ENV (
    if exist "%VIRTUAL_ENV%\Scripts\python.exe" (
        set "PY_CMD=%VIRTUAL_ENV%\Scripts\python.exe"
        echo [环境] 检测到已激活的虚拟环境 (venv): %VIRTUAL_ENV%
        goto FOUND_PY
    )
)

REM 3. 检查本地是否存在 .venv 目录
if exist "%~dp0.venv\Scripts\python.exe" (
    set "PY_CMD=%~dp0.venv\Scripts\python.exe"
    echo [环境] 检测到本地虚拟环境: %~dp0.venv
    goto FOUND_PY
)
if exist "%~dp0..\.venv\Scripts\python.exe" (
    set "PY_CMD=%~dp0..\.venv\Scripts\python.exe"
    echo [环境] 检测到项目虚拟环境: %~dp0..\.venv
    goto FOUND_PY
)

REM 4. 检查 PlatformIO 默认内置 Python (包含完整 esptool)
if exist "%USERPROFILE%\.platformio\penv\Scripts\python.exe" (
    set "PY_CMD=%USERPROFILE%\.platformio\penv\Scripts\python.exe"
    echo [环境] 检测到 PlatformIO 运行环境
    goto FOUND_PY
)

REM 5. 检查系统全局 python
python --version >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    set "PY_CMD=python"
    echo [环境] 使用系统全局 Python
    goto FOUND_PY
)

REM 6. 未找到 Python
echo.
echo [错误] 未检测到可用的 Python 环境！
echo.
echo 请确保已安装 Python / Anaconda / Miniconda，或安装 PlatformIO。
echo 您也可以手动创建虚拟环境:
echo   python -m venv .venv
echo   .venv\Scripts\pip install -r requirements.txt
echo.
pause
exit /b 1

:FOUND_PY
echo [启动] 正在启动烧录界面...
echo.

REM 检查并尝试运行 GUI
"%PY_CMD%" "%~dp0esp32_flash_gui.py"
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [提示] 若缺少依赖包 (pyserial / esptool)，正在尝试自动安装...
    "%PY_CMD%" -m pip install -r "%~dp0requirements.txt"
    echo.
    echo 正在重新启动烧录器...
    "%PY_CMD%" "%~dp0esp32_flash_gui.py"
)

exit /b 0
