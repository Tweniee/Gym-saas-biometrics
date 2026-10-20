; Mac/Docker installer: compiled by native Linux makensis, with Windows x64 payloads.
Unicode true
!include "MUI2.nsh"
!include "x64.nsh"
!include "LogicLib.nsh"
!ifndef ApiUrl
  !error "Supply -DApiUrl=https://YOUR-BACKEND/api/v1"
!endif
!ifndef DistDir
  !define DistDir "/build/dist"
!endif
Name "Zenvore Biometric Connector"
OutFile "${DistDir}/installer/ZenvoreBiometricConnector-0.1.0-windows-x64.exe"
InstallDir "$PROGRAMFILES64\Zenvore\BiometricConnector"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
VIProductVersion "0.1.0.0"
VIAddVersionKey /LANG=1033 "ProductName" "Zenvore Biometric Connector"
VIAddVersionKey /LANG=1033 "FileDescription" "Zenvore Biometric Connector installer"
VIAddVersionKey /LANG=1033 "FileVersion" "0.1.0"
VIAddVersionKey /LANG=1033 "ProductVersion" "0.1.0"
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN "$INSTDIR\setup\ZenvoreConnector.exe"
!define MUI_FINISHPAGE_RUN_PARAMETERS "setup"
!define MUI_FINISHPAGE_RUN_TEXT "Open Connector Setup"
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"
Var StateDir
Var ResultCode
Var ConfigHandle

Function .onInit
  SetShellVarContext all
  SetRegView 64
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "This connector requires 64-bit Windows."
    Abort
  ${EndIf}
  ; Stop before replacing files during an upgrade; allow an absent service.
  ExecWait '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -Command "if (Get-Service ZenvoreBiometricConnector -ErrorAction SilentlyContinue) { Stop-Service ZenvoreBiometricConnector; (Get-Service ZenvoreBiometricConnector).WaitForStatus($\'Stopped$\', $\'00:00:45$\') }"' $ResultCode
  ${If} $ResultCode != 0
    MessageBox MB_ICONSTOP "Could not stop the connector service. Stop it before upgrading."
    Abort
  ${EndIf}
FunctionEnd

Section "Zenvore Connector" MainSection
  SetShellVarContext all
  SetRegView 64
  SetOutPath "$INSTDIR\setup"
  File /r "${DistDir}/ZenvoreConnector/*"
  SetOutPath "$INSTDIR\service"
  File /r "${DistDir}/ZenvoreConnectorService/*"
  StrCpy $StateDir "$APPDATA\Zenvore\BiometricConnector"
  CreateDirectory "$StateDir"
  ExecWait '"$SYSDIR\icacls.exe" "$StateDir" /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F' $ResultCode
  ${If} $ResultCode != 0
    MessageBox MB_ICONSTOP "Could not secure connector state permissions. Setup cannot continue."
    Abort
  ${EndIf}
  IfFileExists "$StateDir\config.json" config_exists
  ClearErrors
  FileOpen $ConfigHandle "$StateDir\config.json" w
  IfErrors config_failed
  FileWrite $ConfigHandle '{"api_url":"${ApiUrl}","development":false}'
  FileClose $ConfigHandle
  IfErrors config_failed
  Goto config_exists
config_failed:
  MessageBox MB_ICONSTOP "Could not write connector configuration."
  Abort
config_exists:
  ; Install on first use, then update the existing service on upgrade.
  ExecWait '"$SYSDIR\sc.exe" query ZenvoreBiometricConnector' $ResultCode
  ${If} $ResultCode == 0
    ExecWait '"$INSTDIR\service\ZenvoreConnectorService.exe" --startup auto update' $ResultCode
  ${Else}
    ExecWait '"$INSTDIR\service\ZenvoreConnectorService.exe" --startup auto install' $ResultCode
  ${EndIf}
  ${If} $ResultCode != 0
    MessageBox MB_ICONSTOP "Could not register the Windows connector service."
    Abort
  ${EndIf}
  ExecWait '"$SYSDIR\sc.exe" config ZenvoreBiometricConnector start= auto' $ResultCode
  ExecWait '"$SYSDIR\sc.exe" failure ZenvoreBiometricConnector reset= 86400 actions= restart/5000/restart/15000/restart/60000' $ResultCode
  ExecWait '"$SYSDIR\sc.exe" start ZenvoreBiometricConnector' $ResultCode
  ${If} $ResultCode != 0
    MessageBox MB_ICONSTOP "The connector service could not start. Check Windows Event Viewer and retry setup."
    Abort
  ${EndIf}
  CreateDirectory "$SMPROGRAMS\Zenvore"
  CreateShortcut "$SMPROGRAMS\Zenvore\Connector Setup.lnk" "$INSTDIR\setup\ZenvoreConnector.exe" "setup"
  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ZenvoreBiometricConnector" "DisplayName" "Zenvore Biometric Connector"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ZenvoreBiometricConnector" "DisplayVersion" "0.1.0"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ZenvoreBiometricConnector" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ZenvoreBiometricConnector" "InstallLocation" "$INSTDIR"
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ZenvoreBiometricConnector" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ZenvoreBiometricConnector" "NoRepair" 1
SectionEnd

Section "Uninstall"
  SetShellVarContext all
  SetRegView 64
  ExecWait '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -Command "if (Get-Service ZenvoreBiometricConnector -ErrorAction SilentlyContinue) { Stop-Service ZenvoreBiometricConnector; (Get-Service ZenvoreBiometricConnector).WaitForStatus($\'Stopped$\', $\'00:00:45$\') }"' $ResultCode
  ${If} $ResultCode != 0
    MessageBox MB_ICONSTOP "Could not stop the connector service. Stop it before uninstalling."
    Abort
  ${EndIf}
  ExecWait '"$SYSDIR\sc.exe" delete ZenvoreBiometricConnector'
  Delete "$SMPROGRAMS\Zenvore\Connector Setup.lnk"
  RMDir "$SMPROGRAMS\Zenvore"
  RMDir /r "$INSTDIR\setup"
  RMDir /r "$INSTDIR\service"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\ZenvoreBiometricConnector"
  ; Preserve ProgramData recovery state. Revoke the installation before retiring the PC.
SectionEnd
