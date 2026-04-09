@echo off
echo Installing PyInstaller if not present...
pip show pyinstaller > nul 2>&1 || pip install pyinstaller
echo Building LockItPro.exe...
python -m PyInstaller --onefile --windowed --name "LockItPro" --icon=icon.ico --upx-dir "C:\Users\Tim\upx" lockitpro.py
echo Done! Executable is in the 'dist' folder.
pause