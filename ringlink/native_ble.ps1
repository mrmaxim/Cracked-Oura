param(
    [ValidateSet('scan', 'pair', 'verify', 'battery', 'events', 'daemon', 'features', 'prepare-offline')]
    [string]$Command = 'scan',
    [switch]$FactoryResetDone,
    [string]$Address
)
$ErrorActionPreference = 'Stop'
$nativePython = Join-Path $PSScriptRoot '../.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $nativePython)) {
    throw 'Create .venv in the repo and install ringlink/requirements-native.txt first.'
}
Push-Location $PSScriptRoot
try {
    if ($Command -eq 'daemon') {
        $nativeKey = Join-Path $env:LOCALAPPDATA 'CrackedOura/ringlink/oura_key.hex'
        if (-not (Test-Path -LiteralPath $nativeKey)) {
            throw 'Pair and verify before starting the daemon.'
        }
        $env:OURA_TRANSPORT = 'native'
        if ($Address) { $env:OURA_ADDRESS = $Address }
        & $nativePython -u ring_daemon.py
    } else {
        $nativeArgs = @('-u', 'oura_bleak.py', $Command)
        if ($FactoryResetDone) { $nativeArgs += '--factory-reset-done' }
        if ($Address) { $nativeArgs += @('--address', $Address) }
        & $nativePython @nativeArgs
    }
    if ($LASTEXITCODE -ne 0) { throw "Native BLE command failed (exit $LASTEXITCODE)." }
} finally {
    Pop-Location
}
