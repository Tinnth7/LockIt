@echo off
title Install LockIt Pro Context Menu
echo Installing LockIt Pro right-click submenu...

set "SCRIPT_DIR=%~dp0"
set "EXE_PATH=%SCRIPT_DIR%LockItPro.exe"

if not exist "%EXE_PATH%" (
    echo ERROR: LockItPro.exe not found in %SCRIPT_DIR%
    echo Place this batch file in the same folder as LockItPro.exe
    pause
    exit /b 1
)

:: For all files (*)
reg add "HKEY_CLASSES_ROOT\*\shell\LockItPro" /v "MUIVerb" /d "LockIt Pro" /f
reg add "HKEY_CLASSES_ROOT\*\shell\LockItPro" /v "SubCommands" /d "" /f
reg add "HKEY_CLASSES_ROOT\*\shell\LockItPro\shell\Lock" /v "MUIVerb" /d "Lock" /f
reg add "HKEY_CLASSES_ROOT\*\shell\LockItPro\shell\Lock\command" /ve /d "\"%EXE_PATH%\" --lock \"%%1\"" /f
reg add "HKEY_CLASSES_ROOT\*\shell\LockItPro\shell\Unlock" /v "MUIVerb" /d "Unlock" /f
reg add "HKEY_CLASSES_ROOT\*\shell\LockItPro\shell\Unlock\command" /ve /d "\"%EXE_PATH%\" --unlock \"%%1\"" /f
reg add "HKEY_CLASSES_ROOT\*\shell\LockItPro\shell\Properties" /v "MUIVerb" /d "Properties" /f
reg add "HKEY_CLASSES_ROOT\*\shell\LockItPro\shell\Properties\command" /ve /d "\"%EXE_PATH%\" --properties \"%%1\"" /f

:: For folders
reg add "HKEY_CLASSES_ROOT\Directory\shell\LockItPro" /v "MUIVerb" /d "LockIt Pro" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\LockItPro" /v "SubCommands" /d "" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\LockItPro\shell\Lock" /v "MUIVerb" /d "Lock Folder" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\LockItPro\shell\Lock\command" /ve /d "\"%EXE_PATH%\" --lock \"%%1\"" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\LockItPro\shell\Unlock" /v "MUIVerb" /d "Unlock Folder" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\LockItPro\shell\Unlock\command" /ve /d "\"%EXE_PATH%\" --unlock \"%%1\"" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\LockItPro\shell\Properties" /v "MUIVerb" /d "Properties" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\LockItPro\shell\Properties\command" /ve /d "\"%EXE_PATH%\" --properties \"%%1\"" /f

echo Done. Right-click any file or folder - LockIt Pro submenu added.
pause