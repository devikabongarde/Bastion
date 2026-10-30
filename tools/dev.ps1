# Start or reuse the local BaselineGuard API and web UI.
# Usage: powershell -File tools/dev.ps1 [-ApiPort 8000] [-WebPort 5173]
param(
    [ValidateRange(1, 65535)][int]$ApiPort = 8000,
    [ValidateRange(1, 65535)][int]$WebPort = 5173
)

$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root
$apiProcess = $null

function Test-LoopbackPort {
    param([int]$Port)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $pending = $client.BeginConnect("127.0.0.1", $Port, $null, $null)
        if (-not $pending.AsyncWaitHandle.WaitOne(700)) { return $false }
        $client.EndConnect($pending)
        return $client.Connected
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

function Test-ApiHealth {
    param([int]$Port)
    try {
        $health = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/health/live" -TimeoutSec 2
        if ($health.status -ne "live") { return $false }
        $spec = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/api/openapi.json" -TimeoutSec 3
        $paths = @($spec.paths.PSObject.Properties.Name)
        $required = @(
            "/api/v1/auth/login",
            "/api/v1/auth/mfa/verify",
            "/api/v1/assessments",
            "/api/v1/imports"
        )
        foreach ($path in $required) {
            if ($path -notin $paths) { return $false }
        }
        return $true
    } catch {
        return $false
    }
}

function Test-BaselineGuardWeb {
    param([int]$Port)
    try {
        $page = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/" -TimeoutSec 3 -UseBasicParsing
        return $page.StatusCode -eq 200 -and $page.Content -match '<title>(BaselineGuard|Bastion)'
    } catch {
        return $false
    }
}

$apiListening = Test-LoopbackPort -Port $ApiPort
$webListening = Test-LoopbackPort -Port $WebPort

if ($apiListening -and -not (Test-ApiHealth -Port $ApiPort)) {
    throw "Port $ApiPort has an older or unrelated API build (required login/import routes are missing). Choose another -ApiPort or stop that service yourself; this script will not terminate it."
}
if ($webListening -and -not (Test-BaselineGuardWeb -Port $WebPort)) {
    throw "Port $WebPort is occupied by another service. Choose -WebPort or stop that service yourself; this script will not terminate it."
}
if ($webListening -and $ApiPort -ne 8000) {
    throw "BaselineGuard UI is already on port $WebPort and uses its existing API proxy. Reuse API port 8000 or stop/restart the UI yourself."
}

$python = Join-Path $root ".venv\Scripts\python.exe"
& $python "tools\seed_demo.py"
if ($LASTEXITCODE -ne 0) { throw "Demo database preparation failed (exit $LASTEXITCODE)." }

try {
    if (-not $apiListening) {
        $logDirectory = Join-Path $root "data\logs"
        New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
        $apiProcess = Start-Process -FilePath $python -ArgumentList @("-m", "uvicorn", "baselineguard_api.main:app", "--host", "127.0.0.1", "--port", "$ApiPort") -WorkingDirectory $root -PassThru -WindowStyle Hidden -RedirectStandardOutput (Join-Path $logDirectory "api-dev.log") -RedirectStandardError (Join-Path $logDirectory "api-dev-error.log")

        $deadline = (Get-Date).AddSeconds(30)
        while ((Get-Date) -lt $deadline) {
            if ($apiProcess.HasExited) {
                throw "The API process exited during startup. Check data/logs/api-dev-error.log."
            }
            if (Test-ApiHealth -Port $ApiPort) { break }
            Start-Sleep -Milliseconds 400
        }
        if (-not (Test-ApiHealth -Port $ApiPort)) {
            throw "The API did not become healthy within 30 seconds. Check data/logs/api-dev-error.log."
        }
    } else {
        Write-Host "Reusing the healthy API already listening on 127.0.0.1:$ApiPort."
    }

    & $python "tools\seed_demo.py" --load --base-url "http://127.0.0.1:$ApiPort"
    if ($LASTEXITCODE -ne 0) { throw "Demo evidence loading failed (exit $LASTEXITCODE)." }

    if ($webListening) {
        Write-Host "Reusing the BaselineGuard UI already listening on 127.0.0.1:$WebPort."
        Write-Host "API: http://127.0.0.1:$ApiPort  UI: http://127.0.0.1:$WebPort"
        if ($null -ne $apiProcess) {
            [void](Read-Host "Press Enter to stop the API process started by this script")
        }
        return
    }

    $env:BG_API_URL = "http://127.0.0.1:$ApiPort"
    Push-Location (Join-Path $root "apps\web")
    try {
        & ".\node_modules\.bin\vite.cmd" --host 127.0.0.1 --port $WebPort
        if ($LASTEXITCODE -ne 0) {
            throw "Vite exited with status $LASTEXITCODE. Select another -WebPort if it is already in use."
        }
    } finally {
        Pop-Location
    }
} finally {
    if ($null -ne $apiProcess -and -not $apiProcess.HasExited) {
        Stop-Process -Id $apiProcess.Id -Force -ErrorAction SilentlyContinue
    }
}

