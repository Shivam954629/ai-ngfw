@echo off
cd /d "%~dp0.."
call venv\Scripts\activate 2>nul
uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000
pause
