; Per-user installer: no administrator rights needed. Build: iscc /DAppVersion=0.1.0 installer\RepoGuard.iss
#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif

[Setup]
AppId={{6A0E2C55-3F0B-4C1D-9C55-5E2B7A9F1D10}
AppName=RepoGuard
AppVersion={#AppVersion}
AppPublisher=RepoGuard
DefaultDirName={localappdata}\Programs\RepoGuard
DefaultGroupName=RepoGuard
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir=Output
OutputBaseFilename=RepoGuard-Setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
UninstallDisplayIcon={app}\RepoGuard.exe
SourceDir=..

[Tasks]
Name: "startup"; Description: "Start RepoGuard when I sign in to Windows"; GroupDescription: "Protection:"
Name: "gitprotect"; Description: "Block git pulls, fetches and clones that bring malware (sets git's global core.hooksPath)"; GroupDescription: "Protection:"

[Files]
Source: "dist\RepoGuard\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion

[Icons]
Name: "{userprograms}\RepoGuard"; Filename: "{app}\RepoGuard.exe"

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "RepoGuard"; \
  ValueData: """{app}\RepoGuard.exe"" --background"; Tasks: startup; Flags: uninsdeletevalue

[Run]
Filename: "{app}\repoguard-cli.exe"; Parameters: "protect on"; Flags: runhidden; Tasks: gitprotect; StatusMsg: "Turning on git protection..."
Filename: "{app}\RepoGuard.exe"; Description: "Open RepoGuard"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{app}\repoguard-cli.exe"; Parameters: "protect off"; Flags: runhidden; RunOnceId: "RepoGuardProtectOff"
