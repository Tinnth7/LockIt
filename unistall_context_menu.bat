@echo off
title Uninstall LockIt Pro Context Menu
echo Removing LockIt Pro right-click submenu...

reg delete "HKEY_CLASSES_ROOT\*\shell\LockItPro" /f
reg delete "HKEY_CLASSES_ROOT\Directory\shell\LockItPro" /f

echo Done.
pause