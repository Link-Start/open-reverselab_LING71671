<#
.SYNOPSIS
    初始化新的 CTF 题目环境
.DESCRIPTION
    创建 case 目录、复制模板、初始化 links.md
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$Name,
    [string]$Url = "",
    [string]$Board = "ctf-website"
)

$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$caseDir = Join-Path $root "cases\$Name"
$templateDir = Join-Path $root "templates\cases"

if (Test-Path $caseDir) {
    Write-Warning "Case directory already exists: $caseDir"
} else {
    New-Item -ItemType Directory -Path $caseDir | Out-Null
    Copy-Item "$templateDir\*" $caseDir -Recurse
    Write-Host "Created: $caseDir"
}

# Initialize links
$linksPath = Join-Path $caseDir "links.md"
@"
# $Name Links

## URL
$Url

## Board
$Board

## Quick Links
- Exports: `exports/$Board/$Name/`
- Notes: `notes/$Board/$Name/`
- Reports: `reports/$Board/$Name/`
"@ | Out-File -FilePath $linksPath -Encoding UTF8

Write-Host "Challenge '$Name' initialized."
Write-Host "Next: cd cases/$Name && read README.md"
