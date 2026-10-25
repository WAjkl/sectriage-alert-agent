@echo off
chcp 65001 >nul
title SecTriage
cd /d "%~dp0"
echo ============================================
echo   SecTriage - starting on http://127.0.0.1:8100
echo   Keep this window open. Ctrl+C to stop.
echo ============================================
python main.py --port 8100
pause
