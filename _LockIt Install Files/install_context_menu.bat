@echo off
set "EXE_PATH=%~dp0LockItPro.exe"

reg add "HKEY_CLASSES_ROOT\*\shell\LockItPro" /v "MUIVerb" /d "LockIt Pro" /f
reg add "HKEY_CLASSES_ROOT\*\shell\LockItPro" /v "SubCommands" /d "" /f
reg add "HKEY_CLASSES_ROOT\*\shell\LockItPro\shell\Lock" /v "MUIVerb" /d "Lock" /f
reg add "HKEY_CLASSES_ROOT\*\shell\LockItPro\shell\Lock\command" /ve /d "\"%EXE_PATH%\" --lock \"%%1\"" /f
reg add "HKEY_CLASSES_ROOT\*\shell\LockItPro\shell\Unlock" /v "MUIVerb" /d "Unlock" /f
reg add "HKEY_CLASSES_ROOT\*\shell\LockItPro\shell\Unlock\command" /ve /d "\"%EXE_PATH%\" --unlock \"%%1\"" /f
reg add "HKEY_CLASSES_ROOT\*\shell\LockItPro\shell\Properties" /v "MUIVerb" /d "Properties" /f
reg add "HKEY_CLASSES_ROOT\*\shell\LockItPro\shell\Properties\command" /ve /d "\"%EXE_PATH%\" --properties \"%%1\"" /f

reg add "HKEY_CLASSES_ROOT\Directory\shell\LockItPro" /v "MUIVerb" /d "LockIt Pro" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\LockItPro" /v "SubCommands" /d "" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\LockItPro\shell\Lock" /v "MUIVerb" /d "Lock Folder" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\LockItPro\shell\Lock\command" /ve /d "\"%EXE_PATH%\" --lock \"%%1\"" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\LockItPro\shell\Unlock" /v "MUIVerb" /d "Unlock Folder" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\LockItPro\shell\Unlock\command" /ve /d "\"%EXE_PATH%\" --unlock \"%%1\"" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\LockItPro\shell\Properties" /v "MUIVerb" /d "Properties" /f
reg add "HKEY_CLASSES_ROOT\Directory\shell\LockItPro\shell\Properties\command" /ve /d "\"%EXE_PATH%\" --properties \"%%1\"" /f

echo Context menu installed.