# Signs one PE file with Azure Trusted Signing (Artifact Signing) through SignTool and the dlib.
# Expects, after azure/login (OIDC) and the release workflow's install step:
#   ACS_DLIB     path to Azure.CodeSigning.Dlib.dll (x64)
#   ACS_METADATA path to metadata.json (endpoint, account, certificate profile)
#   SIGNTOOL     path to signtool.exe
param([Parameter(Mandatory = $true, Position = 0)][string] $FilePath)

$ErrorActionPreference = 'Stop'
foreach ($p in @($FilePath, $env:ACS_DLIB, $env:ACS_METADATA, $env:SIGNTOOL)) {
	if ([string]::IsNullOrWhiteSpace($p) -or -not (Test-Path -LiteralPath $p)) { throw "missing: '$p'" }
}

Write-Host "Signing $FilePath"
& $env:SIGNTOOL sign /v /fd SHA256 /tr 'http://timestamp.acs.microsoft.com' /td SHA256 `
	/dlib $env:ACS_DLIB /dmdf $env:ACS_METADATA $FilePath
if ($LASTEXITCODE -ne 0) { throw "signtool failed for $FilePath (exit $LASTEXITCODE)" }

& $env:SIGNTOOL verify /pa /v $FilePath | Out-Null
if ($LASTEXITCODE -ne 0) { throw "signature verification failed for $FilePath" }
