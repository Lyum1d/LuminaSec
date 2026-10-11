@echo off
rem SRC 渗透 Agent 本地控制台启动脚本（GBK 编码 + CRLF，中文 Windows 原生兼容）
setlocal
cd /d "%~dp0"

echo ============================================================
echo   SRC 渗透 Agent - 本地控制台
echo ============================================================
echo   后端就绪后浏览器会自动打开 http://127.0.0.1:8770
echo   关闭此窗口即停止服务。仅限已获得书面授权的目标测试。
echo ============================================================
echo.

rem ---- 1. 探测 Python 解释器（可移植写法，不写死本机路径）----
rem 顺序：环境变量 SRC_AGENT_PY → 项目 .venv → py 启动器 → PATH python
rem 每个候选都实际执行 --version 验证，绕开 Windows 商店的 python 占位程序
set "PY=%SRC_AGENT_PY%"
if "%PY%"=="" set "PY=%~dp0.venv\Scripts\python.exe"
if exist "%PY%" "%PY%" --version >nul 2>&1 && goto pick_ok
set "PY="
where py >nul 2>&1 && for /f "delims=" %%i in ('py -3 -c "import sys;print(sys.executable)" 2^>nul') do set "PY=%%i"
if defined PY if exist "%PY%" goto pick_ok
set "PY="
where python >nul 2>&1 && for /f "delims=" %%i in ('python -c "import sys;print(sys.executable)" 2^>nul') do set "PY=%%i"
if defined PY if exist "%PY%" goto pick_ok

echo [错误] 未找到可用的 Python（3.10+），无法启动。
echo   请任选其一：
echo     1. 安装 Python 并勾选 Add to PATH，然后重新双击本文件；
echo     2. 设置系统环境变量 SRC_AGENT_PY 指向 python.exe 完整路径；
echo     3. 把 update.exe 放到本目录双击（可引导完成环境准备）。
echo.
pause
exit /b 1

:pick_ok
echo   使用解释器：%PY%
echo.

rem ---- 2. 依赖自检：缺依赖时自动安装（仅首次，清华镜像）----
"%PY%" -c "import fastapi,uvicorn,httpx,yaml" >nul 2>&1
if errorlevel 1 (
  echo   首次运行：正在安装依赖，可能需要几分钟，请勿关闭窗口…
  call :install_deps
  if errorlevel 1 (
    echo [错误] 依赖安装失败。请检查网络后重试本文件，或手动执行：
    echo     "%PY%" -m pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
    echo.
    pause
    exit /b 1
  )
  echo   依赖安装完成。
  echo.
)

rem ---- 3. 启动服务 ----
"%PY%" run.py
echo.
echo 服务已退出。若上方有报错请截图反馈给维护者；按任意键关闭窗口。
pause >nul
exit /b 0

:install_deps
if not exist "requirements.txt" exit /b 1
"%PY%" -m pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple 2>nul
if errorlevel 1 "%PY%" -m pip install -r requirements.txt
exit /b %errorlevel%
