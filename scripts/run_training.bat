@echo off
cd /d "%~dp0.."
call venv\Scripts\activate 2>nul || echo Run: python -m venv venv ^& venv\Scripts\activate
python -m src.models.train
pause
