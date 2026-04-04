@echo off
title Install LockIt Pro Context Menu
echo Installing LockIt Pro right-click menu...

set "SCRIPT_DIR=%~dp0"
set "EXE_PATH=%SCRIPT_DIR%LockItPro.exe"

if not exist "%EXE_PATH%" (
    echo ERROR: LockItPro.exe not found in %SCRIPT_DIR%
    echo Place this batch file in the same folder as LockItPro.exe
    pause
    exit /b 1
)

:: Register for all files
reg add "HKEY_CLASSES_ROOT\*\shell\LockItLock" /ve /d "Lock with LockIt" /f
reg add "HKEY_CLASSES_ROOT\*\shell\LockItLock\command" /ve /d "\"%EXE_PATH%\" --lock \"%%1\"" /f

reg add "HKEY_CLASSES_ROOT\*\shell\LockItUnlock" /ve /d "Unlock with LockIt" /f
reg add "HKEY_CLASSES_ROOT\*\shell\LockItUnlock\command" /ve /d "\"%EXE_PATH%\" --unlock \"%%1\"" /f

reg add "HKEY_CLASSES_ROOT\*\shell\LockItProperties" /ve /d "LockIt File Properties" /f
reg add "HKEY_CLASSES_ROOT\*\shell\LockItProperties\command" /ve /d "\"%EXE_PATH%\" --properties \"%%1\"" /f

:: Register for folders
reg add "HKEY_CLASSES_ROOT\Directory\shell\LockItLock" /ve /d "Lock Folder with LockIt" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\LockItLock\command" /ve /d "\"%EXE_PATH%\" --lock \"%%1\"" /f

reg add "HKEY_CLASSES_ROOT\Directory\shell\LockItUnlock" /ve /d "Unlock Folder with LockIt" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\LockItUnlock\command" /ve /d "\"%EXE_PATH%\" --unlock \"%%1\"" /f

reg add "HKEY_CLASSES_ROOT\Directory\shell\LockItProperties" /ve /d "LockIt Folder Properties" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\LockItProperties\command" /ve /d "\"%EXE_PATH%\" --properties \"%%1\"" /f

echo Done. Right-click any file or folder to see LockIt options.
pause