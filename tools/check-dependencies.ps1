param([string]$Lockfile = '', [string]$OutputFile = 'dependency-audit.json')
$ErrorActionPreference = 'Stop'
$productionRoot = Split-Path -Parent $PSScriptRoot
$lockPath = if ($Lockfile) { [IO.Path]::GetFullPath((Join-Path $productionRoot $Lockfile)) } else { Join-Path $productionRoot 'Cargo.lock' }
$resultsPath = Join-Path $productionRoot 'results'
[IO.Directory]::CreateDirectory($resultsPath) | Out-Null
$outputPath = Join-Path $resultsPath $OutputFile
$utf8 = New-Object System.Text.UTF8Encoding($false)
$lockBytes = [IO.File]::ReadAllBytes($lockPath)
$sha = [Security.Cryptography.SHA256]::Create()
$lockHash = -join ($sha.ComputeHash($lockBytes) | ForEach-Object { $_.ToString('x2') })
$sha.Dispose()
$lockText = [Text.Encoding]::UTF8.GetString($lockBytes)
$dependencies = @()
$localPackages = @()
$unsupported = @()
foreach ($package in [regex]::Matches($lockText, '(?ms)^\[\[package\]\]\r?\n(.*?)(?=^\[\[package\]\]|\z)')) {
    $body = $package.Groups[1].Value
    $name = [regex]::Match($body, '(?m)^name = "([^"]+)"').Groups[1].Value
    $version = [regex]::Match($body, '(?m)^version = "([^"]+)"').Groups[1].Value
    $source = [regex]::Match($body, '(?m)^source = "([^"]+)"').Groups[1].Value
    if (-not $name -or -not $version) { throw 'Unrecognized Cargo.lock package block.' }
    $entry = [ordered]@{ name = $name; version = $version }
    if (-not $source) { $localPackages += $entry }
    elseif ($source -eq 'registry+https://github.com/rust-lang/crates.io-index') { $dependencies += $entry }
    else { $unsupported += $entry }
}
$report = [ordered]@{
    schemaVersion = 1
    recordedAt = [DateTime]::UtcNow.ToString('o')
    status = 'INCOMPLETE'
    method = 'OSV exact-version batch query'
    source = 'https://api.osv.dev/v1/querybatch'
    sourceDocumentation = 'https://google.github.io/osv.dev/api/#operation/OSV_QueryAffectedBatch'
    rustsecExportDocumentation = 'https://rustsec.org/'
    cargoLockSha256 = $lockHash
    registryPackageCount = $dependencies.Count
    queriedPackageCount = 0
    localPackages = $localPackages
    unsupportedSources = $unsupported
    findings = @()
    maintenanceWarningCount = 0
    otherAdvisoryMatchCount = 0
    packageResults = @()
    errors = @()
    publicLaunchAllowed = $false
    limitations = @(
        'Known-advisory matching only; not an audit or proof of code safety.',
        'Includes registry packages recorded in Cargo.lock, including target-specific and development dependencies; reachability is not analyzed.',
        'First-party code, compiler/OS tools, CometBFT Go binary and its dependency graph are not covered.',
        'Availability and freshness depend on OSV and its upstream advisory imports; no independent cargo-audit database run was performed.'
    )
}
$exitStatus = 2
try {
    if ($dependencies.Count -eq 0) { throw 'No registry packages parsed; refusing an empty audit.' }
    $queries = @($dependencies | ForEach-Object {
        [ordered]@{ package = [ordered]@{ name = $_.name; ecosystem = 'crates.io' }; version = $_.version }
    })
    $body = @{ queries = $queries } | ConvertTo-Json -Depth 8 -Compress
    $response = Invoke-RestMethod -Method Post -Uri $report.source -ContentType 'application/json' -Body $body -TimeoutSec 60
    $responseResults = @($response.results)
    if ($responseResults.Count -ne $dependencies.Count) { throw "OSV result count mismatch: expected $($dependencies.Count), received $($responseResults.Count)." }
    for ($index = 0; $index -lt $dependencies.Count; $index++) {
        $dependency = $dependencies[$index]
        $result = $responseResults[$index]
        if ($null -ne $result.error) { throw "OSV package error for $($dependency.name)." }
        if ($result.next_page_token) { throw "OSV pagination required for $($dependency.name); audit incomplete." }
        $vulnerabilities = @($result.vulns | Where-Object { $null -ne $_ })
        $ids = @($vulnerabilities | ForEach-Object { $_.id })
        $report.packageResults += [ordered]@{ name = $dependency.name; version = $dependency.version; advisoryIds = $ids }
        foreach ($vulnerability in $vulnerabilities) {
            if (-not $vulnerability.id) { throw 'OSV returned an advisory without an identifier.' }
            $advisory = Invoke-RestMethod -Uri ('https://api.osv.dev/v1/vulns/' + [Uri]::EscapeDataString($vulnerability.id)) -TimeoutSec 30
            if ($advisory.id -ne $vulnerability.id) { throw 'OSV advisory detail identifier mismatch.' }
            $matchingPackages = @($advisory.affected | Where-Object { $_.package.name -eq $dependency.name -and $_.package.ecosystem -eq 'crates.io' })
            if ($matchingPackages.Count -eq 0) { throw 'OSV advisory detail does not identify the queried package.' }
            $informational = @($matchingPackages | ForEach-Object { $_.database_specific.informational } | Where-Object { $_ } | Select-Object -Unique)
            $report.findings += [ordered]@{
                name = $dependency.name; version = $dependency.version
                advisoryId = $vulnerability.id; modified = $vulnerability.modified
                summary = $advisory.summary; published = $advisory.published; withdrawn = $advisory.withdrawn
                aliases = @($advisory.aliases | Where-Object { $_ })
                informationalCategories = $informational
                severity = @($advisory.severity | Where-Object { $_ })
                affectedRanges = @($matchingPackages | ForEach-Object { $_.ranges })
                references = @($advisory.references)
                url = 'https://osv.dev/vulnerability/' + [Uri]::EscapeDataString($vulnerability.id)
            }
        }
        $report.queriedPackageCount++
    }
    if ($unsupported.Count -gt 0) { throw 'Unsupported dependency sources require a separate audit.' }
    $currentHash = (Get-FileHash -LiteralPath $lockPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($currentHash -ne $lockHash) { throw 'Cargo.lock changed during advisory querying; rerun against the final lockfile.' }
    $report.maintenanceWarningCount = @($report.findings | Where-Object { $_.informationalCategories -contains 'unmaintained' }).Count
    $report.otherAdvisoryMatchCount = $report.findings.Count - $report.maintenanceWarningCount
    if ($report.findings.Count -gt 0) {
        $report.status = 'KNOWN_ADVISORIES_FOUND'
        if ($report.otherAdvisoryMatchCount -eq 0) { $report.status = 'MAINTENANCE_ADVISORIES_REPORTED' }
        $exitStatus = 1
    }
    else { $report.status = 'NO_KNOWN_ADVISORIES_REPORTED'; $exitStatus = 0 }
} catch {
    $report.errors += $_.Exception.Message
}
[IO.File]::WriteAllText($outputPath, ($report | ConvertTo-Json -Depth 12), $utf8)
Write-Output ("Dependency audit: {0}; queried={1}/{2}; advisory matches={3}; errors={4}" -f $report.status, $report.queriedPackageCount, $report.registryPackageCount, $report.findings.Count, $report.errors.Count)
exit $exitStatus
