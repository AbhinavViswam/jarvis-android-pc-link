@echo off
rem Makes .venv here (if missing) and installs the exact packages in requirements.txt. Run again any time.
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  py -3 -m venv .venv 2>nul || python -m venv .venv
)
if not exist ".venv\Scripts\python.exe" (
  echo Python 3 was not found. Install it from python.org, then run this again.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -r requirements.txt
if errorlevel 1 ( pause & exit /b 1 )
echo.
echo Ready. Start JARVIS Link with start.bat.
pause
