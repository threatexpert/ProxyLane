; ProxyLane setup script for Inno Setup 6.
;
; Normally built by scripts\package-release.ps1 -Installer, which stages the
; release files and passes:
;   ISCC /DAppVersion=1.4.0 /DSourceDir=<staging dir> /O<output dir> ProxyLane.iss
;
; Update contract with ProxyLane (see docs/installer-and-updates.md):
; - "ProxyLaneRunning" is held by every ProxyLane process; setup waits for it.
; - "ProxyLaneSetupWaiting" tells an updating ProxyLane that setup is elevated
;   and running, so it can exit and release its files.
; - /AUTOUPDATE (with /SILENT) waits up to 60 seconds for ProxyLane to exit.

#ifndef AppVersion
  #error Pass the release version, for example /DAppVersion=1.4.0
#endif
#ifndef SourceDir
  #error Pass the staged release folder, for example /DSourceDir=..\dist\installer-staging
#endif

[Setup]
AppId={{6B0E3B5C-8F0D-4C1E-9A57-2D3F7C1B9E40}
AppName=ProxyLane
AppVersion={#AppVersion}
AppVerName=ProxyLane {#AppVersion}
AppPublisher=threatexpert
AppPublisherURL=https://github.com/threatexpert/ProxyLane
AppSupportURL=https://github.com/threatexpert/ProxyLane/issues
AppUpdatesURL=https://10000.download/tools
VersionInfoVersion={#AppVersion}
VersionInfoProductName=ProxyLane Setup
VersionInfoDescription=ProxyLane Setup
DefaultDirName={autopf}\ProxyLane
DisableProgramGroupPage=yes
PrivilegesRequired=admin
; 64-bit Windows installs into Program Files with the x64 components.
ArchitecturesAllowed=x86compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=6.1sp1
OutputBaseFilename=ProxyLane-{#AppVersion}-Setup
SetupIconFile=..\src\ProxyLane\res\ProxyLane.ico
UninstallDisplayIcon={app}\ProxyLane.exe
UninstallDisplayName=ProxyLane
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ShowLanguageDialog=auto
; Proxied applications keep ProxyLaneHook*.dll loaded. Restart Manager would
; offer to close them (for example a browser); in-use files are moved aside
; instead, see MoveAside below.
CloseApplications=no
RestartApplications=no

[Languages]
; Inno Setup 6.7.3 ships Simplified Chinese only as an unofficial translation.
; installer\ChineseSimplified.isl is the unmodified copy from the is-6_7_3 tag:
; https://github.com/jrsoftware/issrc/blob/is-6_7_3/Files/Languages/Unofficial/ChineseSimplified.isl
; A copy in the compiler's Languages folder is used when this one is absent.
#if FileExists(AddBackslash(SourcePath) + "ChineseSimplified.isl")
Name: "chinesesimplified"; MessagesFile: "ChineseSimplified.isl"
#elif FileExists(AddBackslash(CompilerPath) + "Languages\ChineseSimplified.isl")
Name: "chinesesimplified"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"
#else
  #pragma warning "ChineseSimplified.isl not found; building an English-only setup."
  #define NoChinese
#endif
Name: "english"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
#ifndef NoChinese
chinesesimplified.ProxyLaneRunning=ProxyLane 正在运行。%n%n请关闭所有 ProxyLane 窗口（包括系统托盘中的图标）后点击“重试”，或点击“取消”退出。
#endif
english.ProxyLaneRunning=ProxyLane is running.%n%nClose every ProxyLane window, including the notification area icon, then click Retry. Click Cancel to quit.
#ifndef NoChinese
chinesesimplified.LaunchProxyLane=启动 ProxyLane
#endif
english.LaunchProxyLane=Launch ProxyLane

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[InstallDelete]
; Files moved aside by an earlier update once their last user exited.
Type: files; Name: "{app}\*.pl-old"

[Files]
Source: "{#SourceDir}\ProxyLane.exe"; DestDir: "{app}"; Flags: ignoreversion uninsrestartdelete; BeforeInstall: MoveAside
Source: "{#SourceDir}\ProxyLaneHook32.dll"; DestDir: "{app}"; Flags: ignoreversion uninsrestartdelete; BeforeInstall: MoveAside
Source: "{#SourceDir}\ProxyLane64.exe"; DestDir: "{app}"; Flags: ignoreversion uninsrestartdelete; BeforeInstall: MoveAside; Check: Is64BitInstallMode
Source: "{#SourceDir}\ProxyLaneHook64.dll"; DestDir: "{app}"; Flags: ignoreversion uninsrestartdelete; BeforeInstall: MoveAside; Check: Is64BitInstallMode
Source: "{#SourceDir}\ProxyLaneSecureTransport64.dll"; DestDir: "{app}"; Flags: ignoreversion uninsrestartdelete; BeforeInstall: MoveAside; Check: Is64BitInstallMode
Source: "{#SourceDir}\ProxyLaneMitm64.dll"; DestDir: "{app}"; Flags: ignoreversion uninsrestartdelete; BeforeInstall: MoveAside; Check: Is64BitInstallMode
Source: "{#SourceDir}\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\README_EN.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\ProxyLane"; Filename: "{app}\{code:MainExecutable}"
Name: "{autodesktop}\ProxyLane"; Filename: "{app}\{code:MainExecutable}"; Tasks: desktopicon

[Run]
; Without skipifsilent this also runs after a /SILENT update, as the user who
; started setup rather than the elevated setup process.
Filename: "{app}\{code:MainExecutable}"; Description: "{cm:LaunchProxyLane}"; Flags: nowait postinstall runasoriginaluser

[UninstallDelete]
Type: files; Name: "{app}\*.pl-old"

[Code]
const
  RunningMutex = 'ProxyLaneRunning';
  SetupWaitingMutex = 'ProxyLaneSetupWaiting';

function MainExecutable(Param: String): String;
begin
  if Is64BitInstallMode then
    Result := 'ProxyLane64.exe'
  else
    Result := 'ProxyLane.exe';
end;

function IsAutoUpdate: Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 1 to ParamCount do
    if CompareText(ParamStr(I), '/AUTOUPDATE') = 0 then
      Result := True;
end;

function WaitForProxyLaneExit(Milliseconds: Integer): Boolean;
var
  Waited: Integer;
begin
  Waited := 0;
  while CheckForMutexes(RunningMutex) and (Waited < Milliseconds) do
  begin
    Sleep(250);
    Waited := Waited + 250;
  end;
  Result := not CheckForMutexes(RunningMutex);
end;

// Silent setups answer the message box with Cancel (/SUPPRESSMSGBOXES).
function EnsureProxyLaneClosed(Milliseconds: Integer): Boolean;
begin
  Result := True;
  while not WaitForProxyLaneExit(Milliseconds) do
  begin
    if SuppressibleMsgBox(CustomMessage('ProxyLaneRunning'), mbError, MB_RETRYCANCEL, IDCANCEL) <> IDRETRY then
    begin
      Result := False;
      Exit;
    end;
    Milliseconds := 0;
  end;
end;

function InitializeSetup: Boolean;
begin
  CreateMutex(SetupWaitingMutex);
  if IsAutoUpdate then
    Result := EnsureProxyLaneClosed(60000)
  else
    Result := EnsureProxyLaneClosed(0);
end;

function InitializeUninstall: Boolean;
begin
  Result := EnsureProxyLaneClosed(0);
end;

// A running proxied application may still map ProxyLaneHook*.dll from {app}.
// Windows allows renaming such a file, so the new version can be written while
// the old image stays valid; [InstallDelete] removes it on a later update.
procedure MoveAside;
var
  Target, Aside: String;
begin
  Target := ExpandConstant(CurrentFileName);
  if FileExists(Target) and not DeleteFile(Target) then
  begin
    Aside := Target + '.' + GetDateTimeString('yyyymmddhhnnsszzz', '-', '-') + '.pl-old';
    if RenameFile(Target, Aside) then
      Log('Moved in-use file aside: ' + Aside)
    else
      Log('Could not move in-use file aside: ' + Target);
  end;
end;
