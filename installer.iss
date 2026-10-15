; TinyAV Inno Setup Script
; Generates TinyAV-Setup.exe installer for Windows
#define MyAppName "TinyAV"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "TinyAV Project"
#define MyAppURL "https://github.com/ankitkaran99/TinyAV"
#define MyAppExeName "TinyAV.exe"

[Setup]
AppId={{D168A789-53BF-4530-9E11-37E4362145A1}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={localappdata}\Programs\{#MyAppName}
DisableProgramGroupPage=yes
OutputDir=dist
OutputBaseFilename=TinyAV-Setup
SetupIconFile=app\assets\icon.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
ArchitecturesInstallIn64BitMode=x64

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "startupicon"; Description: "Launch TinyAV automatically at Windows login (System Tray)"; GroupDescription: "Auto-Start Options:"

[Files]
Source: "dist\TinyAV\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "dist\TinyAV\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon
Name: "{userstartup}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Parameters: "--minimized"; Tasks: startupicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent
