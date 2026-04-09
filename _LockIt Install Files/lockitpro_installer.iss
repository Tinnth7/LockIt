; LockIt Pro Installer Script
[Setup]
AppName=LockIt Pro
AppVersion=1.2
AppPublisher=Lituz
DefaultDirName={pf}\LockItPro
DefaultGroupName=LockIt Pro
UninstallDisplayIcon={app}\LockItPro.exe
Compression=lzma2
SolidCompression=yes
OutputDir=.
OutputBaseFilename=LockItPro_Setup
PrivilegesRequired=admin

[Files]
Source: "LockItPro.exe"; DestDir: "{app}"
Source: "install_context_menu.bat"; DestDir: "{app}"

[Run]
Filename: "{cmd}"; Parameters: "/c ""{app}\install_context_menu.bat"""; Flags: runhidden

[Icons]
Name: "{group}\LockIt Pro"; Filename: "{app}\LockItPro.exe"
Name: "{group}\Uninstall LockIt Pro"; Filename: "{uninstallexe}"

[UninstallRun]
Filename: "{cmd}"; Parameters: "/c reg delete HKEY_CLASSES_ROOT\*\shell\LockItPro /f"; RunOnceId: "DelFileReg"
Filename: "{cmd}"; Parameters: "/c reg delete HKEY_CLASSES_ROOT\Directory\shell\LockItPro /f"; RunOnceId: "DelDirReg"