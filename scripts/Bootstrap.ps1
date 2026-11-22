[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$')]
    [string] $WslDistribution,
    [switch] $SkipInstall,
    [switch] $ReuseBaseline
)

$ErrorActionPreference = 'Stop'
$project = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
Push-Location -LiteralPath $project
try {
    & python -c 'import sys; sys.exit(sys.version_info < (3, 10))'
    if ($LASTEXITCODE -ne 0) { throw 'Python 3.10 or newer is required.' }

    if ($WslDistribution) {
        $engine = "wsl:$WslDistribution"
        & wsl.exe --distribution $WslDistribution --exec /usr/bin/test -x /usr/bin/docker
        if ($LASTEXITCODE -ne 0) {
            if ($SkipInstall) { throw 'Docker Engine is absent from the selected WSL distribution.' }
            & wsl.exe --distribution $WslDistribution --user root --exec /bin/sh -c 'set -eu; apt-get update; DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends docker.io docker-buildx'
            if ($LASTEXITCODE -ne 0) { throw 'Docker Engine installation failed inside WSL.' }
        }
        & wsl.exe --distribution $WslDistribution --user root --exec /usr/bin/systemctl enable --now docker
        if ($LASTEXITCODE -ne 0) { throw 'Docker Engine failed to start. Use an Ubuntu WSL 2 distribution with systemd.' }
        & wsl.exe --distribution $WslDistribution --exec /usr/bin/docker --host 'unix:///var/run/docker.sock' info --format '{{.OSType}}/{{.Architecture}}'
        if ($LASTEXITCODE -ne 0) { throw 'The WSL operator requires access to the local Docker socket.' }
    } else {
        $engine = 'desktop'
        $desktop = Join-Path $env:ProgramFiles 'DockerDockerDocker Desktop.exe'
        $dockerBin = Join-Path $env:ProgramFiles 'DockerDockeresourcesin'
        if (-not (Test-Path -LiteralPath $desktop)) {
            if ($SkipInstall) { throw 'Docker Desktop is absent.' }
            & winget.exe install --id Docker.DockerDesktop --exact --source winget
            if ($LASTEXITCODE -ne 0) { throw 'Docker Desktop installation did not complete.' }
        }
        $env:Path = "$dockerBin;$env:Path"
        & docker.exe --host 'npipe:////./pipe/dockerDesktopLinuxEngine' info --format '{{.OSType}}' 2>$null
        if ($LASTEXITCODE -ne 0) {
            Start-Process -FilePath $desktop -WindowStyle Hidden
            $deadline = (Get-Date).AddSeconds(90)
            do {
                Start-Sleep -Seconds 3
                & docker.exe --host 'npipe:////./pipe/dockerDesktopLinuxEngine' info --format '{{.OSType}}' 2>$null
                $ready = $LASTEXITCODE -eq 0
            } until ($ready -or (Get-Date) -ge $deadline)
            if (-not $ready) { throw 'Docker Desktop did not start its Linux engine. Check Desktop setup or select an Ubuntu WSL distribution.' }
        }
    }

    if (-not $ReuseBaseline) {
        & python -m re_harness.cli provision --engine $engine
        if ($LASTEXITCODE -ne 0) { throw 'The baseline build or provider verification failed.' }
    }
    & python -m re_harness.cli blank
    if ($LASTEXITCODE -ne 0) { throw 'The clean-room check failed.' }
} finally {
    Pop-Location
}
