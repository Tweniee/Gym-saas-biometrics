#ifndef ApiUrl
  #error ApiUrl must be supplied as /DApiUrl=https://api.example.com/api/v1
#endif
[Setup]
AppId={{22F44A87-09DD-4F5B-A8EF-9897B70F4389}
AppName=Zenvore Biometric Connector
AppVersion=0.1.0
DefaultDirName={autopf}\Zenvore\BiometricConnector
DefaultGroupName=Zenvore
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\..\dist\installer
OutputBaseFilename=ZenvoreBiometricConnector-0.1.0-windows-x64
Compression=lzma2
SolidCompression=yes
UninstallDisplayIcon={app}\setup\ZenvoreConnector.exe

[Files]
Source: "..\..\dist\ZenvoreConnector\*"; DestDir: "{app}\setup"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "..\..\dist\ZenvoreConnectorService\*"; DestDir: "{app}\service"; Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{group}\Pair Zenvore Connector"; Filename: "{app}\setup\ZenvoreConnector.exe"; Parameters: "setup"

[Run]
Filename: "{app}\service\ZenvoreConnectorService.exe"; Parameters: "--startup auto install"; Flags: runhidden waituntilterminated
Filename: "{app}\service\ZenvoreConnectorService.exe"; Parameters: "--startup auto update"; Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; Parameters: "config ZenvoreBiometricConnector start= auto"; Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; Parameters: "failure ZenvoreBiometricConnector reset= 86400 actions= restart/5000/restart/15000/restart/60000"; Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; Parameters: "start ZenvoreBiometricConnector"; Flags: runhidden waituntilterminated
Filename: "{app}\setup\ZenvoreConnector.exe"; Parameters: "setup"; Description: "Pair with Zenvore"; Flags: postinstall nowait skipifsilent

[UninstallRun]
Filename: "{sys}\sc.exe"; Parameters: "stop ZenvoreBiometricConnector"; Flags: runhidden waituntilterminated
Filename: "{sys}\sc.exe"; Parameters: "delete ZenvoreBiometricConnector"; Flags: runhidden waituntilterminated

[Code]
function PrepareToInstall(var NeedsRestart: Boolean): String;
var ResultCode: Integer;
begin
  Result := '';
  if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    '-NoProfile -NonInteractive -Command "if (Get-Service ZenvoreBiometricConnector -ErrorAction SilentlyContinue) { Stop-Service ZenvoreBiometricConnector; (Get-Service ZenvoreBiometricConnector).WaitForStatus(''Stopped'', ''00:00:45'') }"',
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode) or (ResultCode <> 0) then
    Result := 'Could not stop the previous connector service. Stop it before upgrading.';
end;

procedure CurStepChanged(CurStep: TSetupStep);
var StateDir, ConfigPath: String; ResultCode: Integer;
begin
  if CurStep = ssPostInstall then begin
    StateDir := ExpandConstant('{commonappdata}\Zenvore\BiometricConnector');
    ForceDirectories(StateDir);
    // Machine DPAPI needs this ACL, shared only by SYSTEM and Administrators.
    if not Exec(ExpandConstant('{sys}\icacls.exe'), '"' + StateDir + '" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode) or (ResultCode <> 0) then
      RaiseException('Failed to restrict connector state directory permissions');
    ConfigPath := StateDir + '\config.json';
    if not FileExists(ConfigPath) then
      if not SaveStringToFile(ConfigPath, '{"api_url":"{#ApiUrl}","development":false}', False) then
        RaiseException('Failed to write connector configuration');
  end;
end;
