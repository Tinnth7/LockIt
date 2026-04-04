@echo off
echo Installing PyInstaller if not present...
pip show pyinstaller > nul 2>&1 || pip install pyinstaller
echo Building LockItPro.exe...
pyinstaller --onefile --windowed --name "LockItPro" --icon=NONE lockitpro.py
echo Done! Executable is in the 'dist' folder.
pause