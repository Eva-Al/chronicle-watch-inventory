@echo off
setlocal
title Chronicle Inventory
cd /d "%~dp0"
where python >nul 2>nul
if errorlevel 1 (
  echo Python was not found. Install Python 3 or add it to PATH.
  pause
  exit /b 1
)
echo Starting Chronicle Inventory on this PC...
echo Keep this window open while using the application.
python "%~dp0server.py" 2>"%~dp0startup-error.log"
set "APP_EXIT=%errorlevel%"
if not "%APP_EXIT%"=="0" (
  echo.
  echo Chronicle Inventory could not start. Error details:
  type "%~dp0startup-error.log"
  echo.
  echo The same details were saved to startup-error.log.
  pause
)
endlocal
