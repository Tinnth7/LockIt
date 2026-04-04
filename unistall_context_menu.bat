@echo off
title Uninstall LockIt Pro Context Menu
echo Removing LockIt Pro right-click menu...

reg delete "HKEY_CLASSES_ROOT\*\shell\LockItLock" /f
reg delete "HKEY_CLASSES_ROOT\*\shell\LockItUnlock" /f
reg delete "HKEY_CLASSES_ROOT\*\shell\LockItProperties" /f
reg delete "HKEY_CLASSES_ROOT\Directory\shell\LockItLock" /f
reg delete "HKEY_CLASSES_ROOT\Directory\shell\LockItUnlock" /f
reg delete "HKEY_CLASSES_ROOT\Directory\shell\LockItProperties" /f

echo Done.
pause