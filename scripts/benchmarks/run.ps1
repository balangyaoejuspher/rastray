param(
    [string]$Target = '',
    [string]$Tool = ''
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path "$PSScriptRoot\..\..").Path
$workdir  = Join-Path $repoRoot 'bench-workdir'
$targetsRoot = Join-Path $workdir 'targets'
$resultsRoot = Join-Path $workdir 'results'
$rastray  = Join-Path $repoRoot 'target\release\rastray.exe'

$catalogue = @(
    [pscustomobject]@{ id='juice-shop';        path='juice-shop';        languages=@('javascript','typescript') }
    [pscustomobject]@{ id='nodegoat';          path='nodegoat';          languages=@('javascript','typescript') }
    [pscustomobject]@{ id='dvwa';              path='dvwa';              languages=@('php') }
    [pscustomobject]@{ id='railsgoat';         path='railsgoat';         languages=@('ruby') }
    [pscustomobject]@{ id='webgoat';           path='webgoat';           languages=@('java') }
    [pscustomobject]@{ id='django-defectdojo'; path='django-defectdojo'; languages=@('python') }
)

$toolList = @('rastray','bandit','semgrep','gosec','gitleaks','eslint-security')

function Is-Applicable {
    param([string]$ToolId, [object]$Target)
    switch ($ToolId) {
        'rastray'         { return $true }
        'semgrep'         { return $true }
        'gitleaks'        { return $true }
        'bandit'          { return $Target.languages -contains 'python' }
        'gosec'           { return $Target.languages -contains 'go' }
        'eslint-security' { return ($Target.languages -contains 'javascript') -or ($Target.languages -contains 'typescript') }
    }
    return $false
}

function Run-Rastray {
    param([string]$TargetDir, [string]$OutDir)
    $jsonPath = Join-Path $OutDir 'rastray.json'
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $jsonText = & $rastray $TargetDir --format json --offline 2>$null
    $sw.Stop()
    $jsonText | Set-Content -Path $jsonPath -Encoding utf8
    $count = 0
    try { $count = (($jsonText | ConvertFrom-Json).findings | Measure-Object).Count } catch {}
    return [pscustomobject]@{ tool='rastray'; version='0.8.0'; findings=$count; elapsed_ms=$sw.ElapsedMilliseconds }
}

function Run-Bandit {
    param([string]$TargetDir, [string]$OutDir)
    $jsonPath = Join-Path $OutDir 'bandit.json'
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $null = & bandit -q -r $TargetDir -f json -o $jsonPath 2>$null
    $sw.Stop()
    $count = 0
    if (Test-Path $jsonPath) {
        try { $count = ((Get-Content $jsonPath -Raw | ConvertFrom-Json).results | Measure-Object).Count } catch {}
    }
    return [pscustomobject]@{ tool='bandit'; version='1.9.4'; findings=$count; elapsed_ms=$sw.ElapsedMilliseconds }
}

function Run-Semgrep {
    param([string]$TargetDir, [string]$OutDir)
    $jsonPath = Join-Path $OutDir 'semgrep.json'
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $jsonText = & docker run --rm -v "${TargetDir}:/src" returntocorp/semgrep:latest semgrep scan --config=p/owasp-top-ten --json --quiet --metrics=off /src 2>$null
    $sw.Stop()
    $jsonText | Set-Content -Path $jsonPath -Encoding utf8
    $count = 0
    try { $count = (($jsonText | ConvertFrom-Json).results | Measure-Object).Count } catch {}
    return [pscustomobject]@{ tool='semgrep'; version='1.165.0'; findings=$count; elapsed_ms=$sw.ElapsedMilliseconds }
}

function Run-Gosec {
    param([string]$TargetDir, [string]$OutDir)
    $jsonPath = Join-Path $OutDir 'gosec.json'
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $null = & docker run --rm -v "${TargetDir}:/src" -w /src securego/gosec:latest -fmt=json -out=/src/.gosec-out.json -quiet ./... 2>$null
    $sw.Stop()
    $src = Join-Path $TargetDir '.gosec-out.json'
    if (Test-Path $src) { Move-Item -Force $src $jsonPath }
    $count = 0
    if (Test-Path $jsonPath) {
        try { $count = ((Get-Content $jsonPath -Raw | ConvertFrom-Json).Issues | Measure-Object).Count } catch {}
    }
    return [pscustomobject]@{ tool='gosec'; version='dev-2026-02-28'; findings=$count; elapsed_ms=$sw.ElapsedMilliseconds }
}

function Run-Gitleaks {
    param([string]$TargetDir, [string]$OutDir)
    $jsonPath = Join-Path $OutDir 'gitleaks.json'
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & docker run --rm -v "${TargetDir}:/src" zricethezav/gitleaks:latest dir /src --report-path /src/.gitleaks-out.json --report-format json --exit-code 0 --no-banner 2>&1 | Out-Null
    } finally {
        $ErrorActionPreference = $prev
    }
    $sw.Stop()
    $src = Join-Path $TargetDir '.gitleaks-out.json'
    if (Test-Path $src) { Move-Item -Force $src $jsonPath }
    $count = 0
    if (Test-Path $jsonPath) {
        try {
            $parsed = Get-Content $jsonPath -Raw | ConvertFrom-Json
            if ($parsed -is [System.Array]) { $count = $parsed.Count } elseif ($parsed) { $count = 1 }
        } catch {}
    }
    return [pscustomobject]@{ tool='gitleaks'; version='v8.30.1'; findings=$count; elapsed_ms=$sw.ElapsedMilliseconds }
}

function Run-EslintSecurity {
    param([string]$TargetDir, [string]$OutDir)
    $jsonPath = Join-Path $OutDir 'eslint-security.json'
    $configDir = Join-Path $OutDir 'eslint-bench'
    New-Item -ItemType Directory -Force -Path $configDir | Out-Null
    $cfg = "import security from 'eslint-plugin-security';`nexport default [{`n  files: ['**/*.js','**/*.jsx','**/*.mjs','**/*.cjs','**/*.ts','**/*.tsx'],`n  plugins: { security },`n  rules: security.configs.recommended.rules`n}];`n"
    $cfg | Set-Content -Path (Join-Path $configDir 'eslint.config.mjs') -Encoding utf8
    Push-Location $configDir
    try {
        if (-not (Test-Path 'node_modules')) {
            $prev = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            try {
                & npm init -y 2>&1 | Out-Null
                & npm install --silent --no-audit --no-fund eslint eslint-plugin-security 2>&1 | Out-Null
            } finally {
                $ErrorActionPreference = $prev
            }
        }
    } finally {
        Pop-Location
    }
    $targetCfg = Join-Path $TargetDir 'eslint.config.mjs'
    $targetNm  = Join-Path $TargetDir 'node_modules'
    $linkedNm  = $false
    $copiedCfg = $false
    if (-not (Test-Path $targetCfg)) {
        Copy-Item (Join-Path $configDir 'eslint.config.mjs') $targetCfg
        $copiedCfg = $true
    }
    if (-not (Test-Path $targetNm)) {
        cmd /c "mklink /J `"$targetNm`" `"$(Join-Path $configDir 'node_modules')`"" | Out-Null
        $linkedNm = $true
    }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        Push-Location $TargetDir
        try {
            $jsonText = & npx --no-install eslint . -f json 2>$null
        } finally {
            Pop-Location
        }
    } finally {
        $ErrorActionPreference = $prev
    }
    $sw.Stop()
    if ($copiedCfg) { Remove-Item $targetCfg -Force -ErrorAction SilentlyContinue }
    if ($linkedNm)  { cmd /c "rmdir `"$targetNm`"" | Out-Null }
    $jsonText | Set-Content -Path $jsonPath -Encoding utf8
    $count = 0
    try {
        $arr = $jsonText | ConvertFrom-Json
        foreach ($file in $arr) { $count += $file.messages.Count }
    } catch {}
    return [pscustomobject]@{ tool='eslint-security'; version='node18+plugin-security3'; findings=$count; elapsed_ms=$sw.ElapsedMilliseconds }
}

function Invoke-Tool {
    param([string]$ToolId, [string]$TargetDir, [string]$OutDir)
    switch ($ToolId) {
        'rastray'         { return Run-Rastray         -TargetDir $TargetDir -OutDir $OutDir }
        'bandit'          { return Run-Bandit          -TargetDir $TargetDir -OutDir $OutDir }
        'semgrep'         { return Run-Semgrep         -TargetDir $TargetDir -OutDir $OutDir }
        'gosec'           { return Run-Gosec           -TargetDir $TargetDir -OutDir $OutDir }
        'gitleaks'        { return Run-Gitleaks        -TargetDir $TargetDir -OutDir $OutDir }
        'eslint-security' { return Run-EslintSecurity  -TargetDir $TargetDir -OutDir $OutDir }
    }
}

$activeTargets = if ($Target) { $catalogue | Where-Object { $_.id -eq $Target } } else { $catalogue }
$activeTools   = if ($Tool)   { $toolList  | Where-Object { $_ -eq $Tool } }       else { $toolList }

if (-not (Test-Path $resultsRoot)) { New-Item -ItemType Directory -Force -Path $resultsRoot | Out-Null }

$summaryPath = Join-Path $resultsRoot 'summary.json'
$summary = @()
if (Test-Path $summaryPath) {
    try {
        $existing = Get-Content $summaryPath -Raw | ConvertFrom-Json
        if ($existing) { $summary = @($existing) }
    } catch {}
}
foreach ($t in $activeTargets) {
    $targetDir = Join-Path $targetsRoot $t.path
    if (-not (Test-Path $targetDir)) { Write-Host "skip $($t.id): not cloned"; continue }
    $outDir = Join-Path $resultsRoot $t.id
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null

    foreach ($toolId in $activeTools) {
        if (-not (Is-Applicable -ToolId $toolId -Target $t)) {
            Write-Host ("{0,-18} {1,-16} N/A" -f $t.id, $toolId)
            continue
        }
        Write-Host ("{0,-18} {1,-16} running..." -f $t.id, $toolId) -NoNewline
        try {
            $r = Invoke-Tool -ToolId $toolId -TargetDir $targetDir -OutDir $outDir
            Write-Host (" {0,5} findings  {1,7:N0} ms" -f $r.findings, $r.elapsed_ms)
            $summary = @($summary | Where-Object { -not ($_.target -eq $t.id -and $_.tool -eq $toolId) })
            $summary += [pscustomobject]@{
                target     = $t.id
                tool       = $toolId
                version    = $r.version
                findings   = $r.findings
                elapsed_ms = $r.elapsed_ms
            }
        } catch {
            Write-Host " ERROR: $_"
            $summary = @($summary | Where-Object { -not ($_.target -eq $t.id -and $_.tool -eq $toolId) })
            $summary += [pscustomobject]@{
                target     = $t.id
                tool       = $toolId
                version    = ''
                findings   = $null
                elapsed_ms = $null
                error      = $_.Exception.Message
            }
        }
    }
}

$summaryPath = Join-Path $resultsRoot 'summary.json'
$summary | ConvertTo-Json -Depth 4 | Set-Content -Path $summaryPath -Encoding utf8
Write-Host "`nsummary written to $summaryPath"
$summary | Format-Table -AutoSize target,tool,findings,elapsed_ms