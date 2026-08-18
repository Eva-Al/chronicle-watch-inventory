@echo off
cd /d "%~dp0"
python backup.py
if errorlevel 1 pause
