param([Parameter(Mandatory=$true)][string]$ServerExe)
$ErrorActionPreference = 'Stop'
$server = (Resolve-Path -LiteralPath $ServerExe).Path
if ([IO.Path]::GetFileName($server) -ne 'enshrouded_server.exe') { throw 'Select enshrouded_server.exe.' }
$running = Get-CimInstance Win32_Process -Filter "Name='enshrouded_server.exe'" | Where-Object { $_.ExecutablePath -and [string]::Equals($_.ExecutablePath, $server, [StringComparison]::OrdinalIgnoreCase) }
if ($running) { throw 'Server already running. Stop it normally first.' }
& (Join-Path $PSScriptRoot 'esm_admission_launcher.exe') $server (Join-Path $PSScriptRoot 'esm_admission.dll')
if ($LASTEXITCODE -ne 0) { throw 'Startup refused. Check esm-admission.txt and esm-admission.log.' }
