Write-Host "Setting up the environment..."
param (
    [string]$pythonScriptPath = ".\main.py",
    [string]$batFileName = "fabt.bat",
    [string]$targetPath = "$env:USERPROFILE\AppData\Local\Programs\Microsoft VS Code\bin"
)

$currentDir = Get-Location

$pythonScriptFullPath = Resolve-Path -Path (Join-Path -Path $currentDir -ChildPath $pythonScriptPath)

if (-not (Test-Path -Path $targetPath)) {
    New-Item -Path $targetPath -ItemType Directory -Force
}

$batContent = "@echo off`n"
$batContent += "`"" + (Get-Command python).Source + "`" `"" + $pythonScriptFullPath + "`" " + " %*"

$batFilePath = Join-Path -Path $targetPath -ChildPath $batFileName

New-Item -Path $batFilePath -ItemType File -Force
Set-Content -Path $batFilePath -Value $batContent

Write-Host "Done! Run 'fabt -v' to start the program."
