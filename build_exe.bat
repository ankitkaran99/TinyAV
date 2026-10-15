@echo off
setlocal
cd /d "%~dp0"

echo ===================================================================
echo               TinyAV - Build Standalone Executable
echo ===================================================================
echo.
echo Building click-and-run standalone TinyAV.exe for Windows...
echo No Python will be required for end-users to run the packaged app.
echo.

python build.py

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Build failed. Please inspect the log messages above.
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo Standalone build finished successfully!
echo Executable: dist\TinyAV\TinyAV.exe
echo Archive   : dist\TinyAV-Portable.zip
echo.
pause
