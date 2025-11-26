@echo off
echo ===============================
echo   🚀 Starting Currency Converter
echo ===============================

REM 1) فتح نافذة جديدة لتشغيل السيرفر
start "Flask Server" cmd /k "cd /d \"%~dp0\" && call venv\Scripts\activate && cd currency_converter_project && python app.py"

REM 2) الانتظار 3 ثواني حتى يشتغل السيرفر
timeout /t 3 /nobreak >nul

REM 3) فتح Google Chrome على الموقع
start "" "C:\Program Files\Google\Chrome\Application\chrome.exe" "http://127.0.0.1:5000/login"

REM لو كان كروم في Program Files (x86) بدل هذا المسار:
REM start "" "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" "http://127.0.0.1:5000/login"

exit