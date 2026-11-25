@echo off
chcp 65001 >nul
title NIDS SOC Admin Dashboard
echo ============================================================
echo   Запуск NIDS SOC Admin Dashboard (http://127.0.0.1:8000)
echo ============================================================
py -3.12 "%~dp0server.py" --open
pause
