@echo off
setlocal enabledelayedexpansion

title "TinyAV - Windows Startup & Tray Shortcut Setup"

:: Determine directory of this script
set "SCRIPT_DIR=%~dp0"
:: Remove trailing backslash
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"

set "MAIN_PY=%SCRIPT_DIR%\main.py"
set "ICON_FILE=%SCRIPT_DIR%\app\assets\icon.ico"
set "EXE_FILE=%SCRIPT_DIR%\dist\TinyAV.exe"

set "STARTUP_DIR=%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
set "DESKTOP_DIR=%USERPROFILE%\Desktop"
set "START_MENU_DIR=%APPDATA%\Microsoft\Windows\Start Menu\Programs"

set "STARTUP_LNK=%STARTUP_DIR%\TinyAV.lnk"
set "DESKTOP_LNK=%DESKTOP_DIR%\TinyAV.lnk"
set "START_MENU_LNK=%START_MENU_DIR%\TinyAV.lnk"

:: 1. Locate pythonw.exe or python.exe
set "PYTHONW_EXE="
set "PYTHON_EXE="

:: Check for bundled executable first
if exist "%EXE_FILE%" (
    set "TARGET_EXE=%EXE_FILE%"
    set "TARGET_ARGS=--minimized"
    set "TARGET_DESC=TinyAV Standalone Executable"
    goto LOCATED_TARGET
)

:: Check current environment's Python
for /f "delims=" %%I in ('python -c "import sys, os; print(os.path.join(os.path.dirname(sys.executable), 'pythonw.exe'))" 2^>nul') do (
    if exist "%%I" set "PYTHONW_EXE=%%I"
)

if not defined PYTHONW_EXE (
    for /f "delims=" %%I in ('where pythonw.exe 2^>nul') do (
        if exist "%%I" (
            set "PYTHONW_EXE=%%I"
            goto FOUND_PYW
        )
    )
)
:FOUND_PYW

if not defined PYTHONW_EXE (
    for /f "delims=" %%I in ('where python.exe 2^>nul') do (
        if exist "%%I" (
            set "PYTHON_EXE=%%I"
            goto FOUND_PY
        )
    )
)
:FOUND_PY

if defined PYTHONW_EXE (
    set "TARGET_EXE=%PYTHONW_EXE%"
    set "TARGET_ARGS=\"%MAIN_PY%\" --minimized"
    set "TARGET_DESC=Pythonw Background Runner (No console window)"
) else if defined PYTHON_EXE (
    set "TARGET_EXE=%PYTHON_EXE%"
    set "TARGET_ARGS=\"%MAIN_PY%\" --minimized"
    set "TARGET_DESC=Python Runner"
) else (
    echo [ERROR] Neither pythonw.exe nor python.exe could be located in PATH.
    echo Please ensure Python is installed and added to PATH.
    pause
    exit /b 1
)

:LOCATED_TARGET

:: Check for CLI arguments for silent automation
if /i "%~1"=="--enable" goto DO_ENABLE_STARTUP
if /i "%~1"=="--disable" goto DO_DISABLE_STARTUP
if /i "%~1"=="--desktop" goto DO_CREATE_DESKTOP
if /i "%~1"=="--run" goto DO_RUN_MINIMIZED

:MENU
cls
echo =====================================================================
echo                 TinyAV - Windows Startup & Tray Setup                
echo =====================================================================
echo.
echo Target Executable : %TARGET_EXE%
echo Target Arguments  : %TARGET_ARGS%
echo Working Directory : %SCRIPT_DIR%
if exist "%ICON_FILE%" (
    echo Shortcut Icon     : %ICON_FILE%
) else (
    echo Shortcut Icon     : Default Windows icon
)
echo.
echo Status:
if exist "%STARTUP_LNK%" (
    echo   Auto-Start at Login : [ENABLED] (Shortcut present in Startup folder)
) else (
    echo   Auto-Start at Login : [DISABLED]
)
if exist "%DESKTOP_LNK%" (
    echo   Desktop Shortcut    : [INSTALLED]
) else (
    echo   Desktop Shortcut    : [NOT INSTALLED]
)
echo.
echo ---------------------------------------------------------------------
echo Choose an option:
echo.
echo   [1] Enable Auto-Start at Windows Login (Directly to System Tray)
echo   [2] Disable / Remove Auto-Start from Windows Login
echo   [3] Create Desktop Shortcut (Starts directly in System Tray)
echo   [4] Create Start Menu Program Shortcut
echo   [5] Launch TinyAV Now in Background (Minimized to Tray)
echo   [6] Exit
echo.
set /p "CHOICE=Enter choice [1-6]: "

if "%CHOICE%"=="1" goto DO_ENABLE_STARTUP
if "%CHOICE%"=="2" goto DO_DISABLE_STARTUP
if "%CHOICE%"=="3" goto DO_CREATE_DESKTOP
if "%CHOICE%"=="4" goto DO_CREATE_START_MENU
if "%CHOICE%"=="5" goto DO_RUN_MINIMIZED
if "%CHOICE%"=="6" goto END

echo Invalid selection. Please try again.
timeout /t 2 >nul
goto MENU


:DO_ENABLE_STARTUP
echo.
echo [*] Configuring silent auto-start at Windows login (zero console windows)...
:: 1. Add to HKCU Run key for 100% silent launch directly by Windows Explorer
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "TinyAV" /t REG_SZ /d "\"%TARGET_EXE%\" %TARGET_ARGS%" /f >nul
:: 2. Also ensure Startup shortcut is in place targeting pythonw.exe with Minimized WindowStyle
call :CREATE_SHORTCUT "%STARTUP_LNK%" "%TARGET_ARGS%" "TinyAV Antivirus (Minimized to System Tray)"
echo [SUCCESS] TinyAV is configured to start automatically at login.
echo           No cmd or console windows will appear at startup.
if "%~1"=="" (
    pause
    goto MENU
)
exit /b 0


:DO_DISABLE_STARTUP
echo.
echo [*] Disabling auto-start at Windows login...
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "TinyAV" /f >nul 2>&1
if exist "%STARTUP_LNK%" (
    del /f /q "%STARTUP_LNK%"
)
echo [SUCCESS] Auto-start disabled (removed registry entry and startup shortcuts).
if "%~1"=="" (
    pause
    goto MENU
)
exit /b 0


:DO_CREATE_DESKTOP
echo.
echo [*] Creating Desktop shortcut...
call :CREATE_SHORTCUT "%DESKTOP_LNK%" "%TARGET_ARGS%" "TinyAV - ClamAV Antivirus Companion"
if exist "%DESKTOP_LNK%" (
    echo [SUCCESS] Desktop shortcut created successfully.
) else (
    echo [ERROR] Failed to create desktop shortcut.
)
if "%~1"=="" (
    pause
    goto MENU
)
exit /b 0


:DO_CREATE_START_MENU
echo.
echo [*] Creating Start Menu shortcut...
call :CREATE_SHORTCUT "%START_MENU_LNK%" "%TARGET_ARGS%" "TinyAV - ClamAV Antivirus Companion"
if exist "%START_MENU_LNK%" (
    echo [SUCCESS] Start Menu shortcut created successfully.
) else (
    echo [ERROR] Failed to create Start Menu shortcut.
)
if "%~1"=="" (
    pause
    goto MENU
)
exit /b 0


:DO_RUN_MINIMIZED
echo.
echo [*] Launching TinyAV directly into the system tray...
start "" "%TARGET_EXE%" %TARGET_ARGS%
echo [SUCCESS] TinyAV launched in background. Check your notification area (taskbar tray).
if "%~1"=="" (
    timeout /t 3 >nul
    goto MENU
)
exit /b 0


:: Helper subroutine to create .lnk via PowerShell WScript.Shell
:CREATE_SHORTCUT
set "SHORTCUT_PATH=%~1"
set "SHORTCUT_ARGS=%~2"
set "SHORTCUT_DESC=%~3"

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$ws = New-Object -ComObject WScript.Shell; " ^
    "$s = $ws.CreateShortcut('%SHORTCUT_PATH%'); " ^
    "$s.TargetPath = '%TARGET_EXE%'; " ^
    "$s.Arguments = '%SHORTCUT_ARGS%'; " ^
    "$s.WorkingDirectory = '%SCRIPT_DIR%'; " ^
    "$s.Description = '%SHORTCUT_DESC%'; " ^
    "$s.WindowStyle = 7; " ^
    "if (Test-Path '%ICON_FILE%') { $s.IconLocation = '%ICON_FILE%,0' }; " ^
    "$s.Save()"
exit /b 0

:END
endlocal
