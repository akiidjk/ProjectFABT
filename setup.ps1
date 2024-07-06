Write-Host "Setting up the environment..."
param (
    [string]$pythonScriptPath = ".\main.py",
    [string]$batFileName = "fabt.bat",
    [string]$targetPath = "$env:USERPROFILE\AppData\Local\Programs\Microsoft VS Code\bin"
)

# Ottieni la directory corrente
$currentDir = Get-Location

# Converti il percorso relativo in uno assoluto
$pythonScriptFullPath = Resolve-Path -Path (Join-Path -Path $currentDir -ChildPath $pythonScriptPath)

# Crea la directory di destinazione se non esiste
if (-not (Test-Path -Path $targetPath)) {
    New-Item -Path $targetPath -ItemType Directory -Force
}

# Contenuto del file batch
$batContent = "@echo off`n"
$batContent += "`"" + (Get-Command python).Source + "`" `"" + $pythonScriptFullPath + "`" " + " %*"

# Percorso completo del file batch
$batFilePath = Join-Path -Path $targetPath -ChildPath $batFileName

# Crea il file batch
New-Item -Path $batFilePath -ItemType File -Force
Set-Content -Path $batFilePath -Value $batContent

Write-Host "Done! Run 'fabt -v' to start the program."
