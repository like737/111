@echo off
chcp 65001 >nul
title 安装 eyilianjie 拦截扩展（Edge）
cd /d "%~dp0"

echo ============================================================
echo   给 Edge 安装「eyilianjie 拦截守卫」扩展
echo   ------------------------------------------------------------
echo   1) 打开 Edge 地址栏输入:  edge://extensions/
echo      并打开左下角的「开发人员模式」开关
echo   2) 点「加载解压缩的扩展」，选择这个目录:
echo      %~dp0guard\extension
echo   3) 装好后：打开被拦的链接会显示我们自己的拦截页（HTTPS 站点同样生效）
echo      想确认扩展是否正常: 点扩展图标 -^> 「运行自检」
echo   ------------------------------------------------------------
echo   注意: 本扩展只负责「导航前预检 + 显示拦截页」;
echo         判定规则与开关仍在 guard 里
echo         (Web 端 http://127.0.0.1:5000/ -^> 导航栏「拦截」-^> 点【开始拦截】)
echo ============================================================
echo.
echo [1/2] 正在打开扩展所在目录（方便你在选择目录时直接选中它）...
start "" explorer "%~dp0guard\extension"
echo.
echo [2/2] 尝试自动打开 Edge 扩展管理页（若没弹出请手动输入 edge://extensions/）...
start "" msedge.exe "edge://extensions/"
echo.
pause
