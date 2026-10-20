param([Parameter(Mandatory=$true)][string]$ApiUrl)
$ErrorActionPreference = 'Stop'
if (-not $IsWindows -and $env:OS -ne 'Windows_NT') { throw 'Build on Windows' }
if ($ApiUrl -notmatch '^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9_-]+)*/api/v1$') {
  throw 'An HTTPS API URL ending in /api/v1 is required'
}
Push-Location (Resolve-Path "$PSScriptRoot/../..")
try {
  python -m pip install '.[build]'
  if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed' }
  python -m unittest discover -s tests -v
  if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
  python -m PyInstaller --noconfirm --clean --onedir --name ZenvoreConnector --uac-admin --collect-all tzdata --hidden-import win32timezone --hidden-import win32crypt packaging/windows/connector_entry.py
  if ($LASTEXITCODE -ne 0) { throw 'Setup build failed' }
  python -m PyInstaller --noconfirm --clean --onedir --name ZenvoreConnectorService --hidden-import win32timezone --hidden-import win32crypt --collect-all tzdata src/zenvore_connector/windows_service.py
  if ($LASTEXITCODE -ne 0) { throw 'Service build failed' }
  $inno = Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'Inno Setup 6/ISCC.exe'
  & $inno "/DApiUrl=$ApiUrl" packaging/windows/installer.iss
  if ($LASTEXITCODE -ne 0) { throw 'Installer build failed' }
  Get-FileHash 'dist/installer/ZenvoreBiometricConnector-0.1.0-windows-x64.exe' -Algorithm SHA256
} finally { Pop-Location }
