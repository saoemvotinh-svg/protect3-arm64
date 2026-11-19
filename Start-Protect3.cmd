@echo off
setlocal
cd /d "%~dp0"
if exist "release\portable\Protect3\Protect3.exe" (
    start "" "release\portable\Protect3\Protect3.exe"
    exit /b 0
)
python -c "import PySide6" >nul 2>&1
if not errorlevel 1 (
    python protect3_cli.py gui
    if errorlevel 1 pause
    exit /b 0
)
py -3 protect3_cli.py gui
if errorlevel 1 pause
