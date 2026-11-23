param([string]$OutputFile = 'cometbft-updated.exe')
$ErrorActionPreference='Stop'
$productionRoot=Split-Path -Parent $PSScriptRoot
$env:GOTOOLCHAIN='go1.27.3'
$env:CGO_ENABLED='0'
$metadataText=go mod download -json github.com/cometbft/cometbft@v0.38.26
if ($LASTEXITCODE -ne 0) { throw 'Upstream module download failed.' }
$metadata=$metadataText | ConvertFrom-Json
if ($metadata.Sum -ne 'h1:MIPYgOSvyyiN1jo3SZljKy4ZXqs896aQnj3pQFfUmaE=' -or $metadata.Origin.Hash -ne '94d77f9f51a72e2b7d832798859f6222f08028f8') { throw 'Upstream source pin changed.' }
$buildDirectory=Join-Path $productionRoot ('.tools/comet-rebuild-'+[guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($buildDirectory) | Out-Null
Get-ChildItem -LiteralPath $metadata.Dir -Force | Copy-Item -Destination $buildDirectory -Recurse
Get-ChildItem -LiteralPath $buildDirectory -Recurse -File -Force | ForEach-Object { $_.IsReadOnly=$false }
Copy-Item -LiteralPath (Join-Path $productionRoot 'consensus/go.mod') -Destination (Join-Path $buildDirectory 'go.mod')
Copy-Item -LiteralPath (Join-Path $productionRoot 'consensus/go.sum') -Destination (Join-Path $buildDirectory 'go.sum')
$binaryPath=Join-Path $productionRoot ('.tools/bin/'+$OutputFile)
Push-Location -LiteralPath $buildDirectory
try {
    go mod verify
    if ($LASTEXITCODE -ne 0) { throw 'Dependency checksum verification failed.' }
    go build -mod=readonly -trimpath -ldflags '-X github.com/cometbft/cometbft/version.TMGitCommitHash=94d77f9f51a72e2b7d832798859f6222f08028f8-tc-dependencies-1' -o $binaryPath ./cmd/cometbft
    if ($LASTEXITCODE -ne 0) { throw 'Consensus binary build failed.' }
} finally { Pop-Location }
Write-Output ('Built pinned local consensus variant: '+$binaryPath)
Write-Output ('SHA256: '+(Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256).Hash.ToLowerInvariant())
