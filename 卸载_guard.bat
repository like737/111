@echo off
chcp 65001 >nul
title 卸载 eyilianjie guard（还原系统代理 + 删除新增文件）
cd /d "%~dp0"

if "%~1"=="" goto :prepare
goto :cleanup

:prepare
set PY=python
if exist ".venv\Scripts\python.exe" set PY=.venv\Scripts\python.exe
echo ============================================================
echo   卸载 guard：
echo     1) 还原系统代理
echo     2) 把 web_app.py / templates\base.html 还原成接入前的版本
echo        （拦截控制台是"融入 web 端"的改动, 备份在 guard\backup\）
echo     3) 删除新增文件（guard\ 目录与入口脚本）
echo   你自己的检测数据、黑名单、检测日志都不会被动
echo ============================================================
echo.
echo [1/4] 还原系统代理...
%PY% -m guard sysproxy off
echo.
echo [2/4] 还原被改过的两个文件（如果存在备份）...
if exist "guard\backup\web_app.py.orig" (
    copy /y "guard\backup\web_app.py.orig" "web_app.py" >nul && echo   已还原 web_app.py
) else (
    echo   没有找到 web_app.py 备份, 跳过（请手工检查 web_app.py 里的 guard 段落）
)
if exist "guard\backup\base.html.orig" (
    copy /y "guard\backup\base.html.orig" "templates\base.html" >nul && echo   已还原 templates\base.html
) else (
    echo   没有找到 base.html 备份, 跳过（请手工检查模板里的「拦截」导航项）
)
echo.
echo [3/4] 复制卸载脚本到临时目录（否则无法删除自己）...
copy /y "%~f0" "%TEMP%\ey_guard_uninstall.bat" >nul
echo [4/4] 开始清理...
start "" cmd /c "%TEMP%\ey_guard_uninstall.bat" "%~dp0"
exit /b

:cleanup
if not "%~1"=="" cd /d "%~1"
timeout /t 1 /nobreak >nul
echo 正在删除 guard\ 目录...
rd /s /q "guard" 2>nul
echo 正在删除新增的脚本与说明...
del /q "run_guarded.py" 2>nul
del /q "安装_Edge扩展.bat" "GUARD_README.md" 2>nul
del /q "%TEMP%\ey_guard_uninstall.bat" 2>nul
echo.
echo 卸载完成。eyilianjie 回到接入前的状态, 用原来的方式启动即可。
echo.
echo 提醒: 如果你装过 Edge 扩展「eyilianjie 拦截守卫」, 请到 edge://extensions/
echo       手动把它移除（浏览器扩展只能由浏览器自己卸载, 脚本无法代劳）。
echo.
pause
