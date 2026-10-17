# vpclab from Windows: forwards every command to scripts/vpclab.sh in WSL.
#
#   .\vpclab up | status | down | reset [--yes] | sh <name|id> | logs | plan | dashboard [stop]
#
# "dashboard" also opens the dashboard in the default browser.
#
# WSL stops the distro (and with it Docker, Floci and the lab) about 15 s
# after the last WSL process ends. "up" therefore starts a hidden
# "wsl.exe ... sleep infinity" that keeps the distro running; "down" stops it.
$ErrorActionPreference = 'Stop'
$Distro = 'Ubuntu-24.04'

function Get-KeepAlive {
    Get-CimInstance Win32_Process -Filter "Name = 'wsl.exe'" |
        Where-Object { $_.CommandLine -like "*-d $Distro --exec sleep infinity*" }
}

function Start-KeepAlive {
    if (-not (Get-KeepAlive)) {
        # One string: Start-Process joins an argument array without quoting.
        Start-Process -WindowStyle Hidden -FilePath wsl.exe -ArgumentList "-d $Distro --exec sleep infinity"
    }
}

function Stop-KeepAlive {
    Get-KeepAlive | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
}

$command = if ($args.Count -gt 0) { $args[0] } else { '' }
if ($command -eq 'up' -or $command -eq 'reset') {
    Start-KeepAlive
}

wsl.exe -d $Distro --cd $PSScriptRoot --exec bash scripts/vpclab.sh @args
$code = $LASTEXITCODE

if ($command -eq 'dashboard' -and $args.Count -eq 1 -and $code -eq 0) {
    Start-Process 'http://localhost:4577'
}
if ($command -eq 'down' -and $code -eq 0) {
    Stop-KeepAlive
}
if ($command -eq 'status') {
    if (Get-KeepAlive) { 'WSL keep-alive  running' } else { 'WSL keep-alive  not running (the distro stops when the last WSL window closes)' }
}
exit $code
