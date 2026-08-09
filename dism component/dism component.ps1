<# 
    Windows Component Store Maintenance Script
    ---------------------------------------------------------
    - Runs DISM /AnalyzeComponentStore
    - Logs output to a timestamped file
    - Performs StartComponentCleanup
    - Automatically decides whether to run /ResetBase
    ---------------------------------------------------------
#>

# --- CONFIGURATION ---
$LogFolder = "$env:SystemDrive\WinSxS_Logs"
$ThresholdMB = 500       # If reclaimable space > 500 MB, ResetBase becomes recommended

# --- PREPARE LOGGING ---
if (!(Test-Path $LogFolder)) {
    New-Item -ItemType Directory -Path $LogFolder | Out-Null
}

$Timestamp = (Get-Date).ToString("yyyy-MM-dd_HH-mm-ss")
$LogFile = "$LogFolder\ComponentStore_$Timestamp.log"

Write-Host "Running DISM analysis..."
"=== DISM Component Store Analysis ($Timestamp) ===" | Out-File $LogFile

# --- RUN ANALYSIS ---
$Analysis = dism.exe /online /cleanup-image /AnalyzeComponentStore
$Analysis | Out-File -Append $LogFile

Write-Host "Analysis complete. Log saved to $LogFile"

# --- PARSE ANALYSIS OUTPUT ---
$Reclaimable = ($Analysis | Select-String "Reclaimable Space").ToString()
$Recommended = ($Analysis | Select-String "Component Store Cleanup Recommended").ToString()

# Extract numeric MB value
$ReclaimMB = 0
if ($Reclaimable -match "(\d+)\s*MB") {
    $ReclaimMB = [int]$matches[1]
}

Write-Host "Reclaimable space detected: $ReclaimMB MB"

# --- PERFORM STANDARD CLEANUP ---
Write-Host "Performing StartComponentCleanup..."
"=== StartComponentCleanup ===" | Out-File -Append $LogFile
dism.exe /online /cleanup-image /StartComponentCleanup | Out-File -Append $LogFile

# --- DECISION LOGIC FOR RESETBASE ---
$RunResetBase = $false

if ($Recommended -match "Yes") {
    Write-Host "DISM recommends cleanup → ResetBase allowed."
    $RunResetBase = $true
}

if ($ReclaimMB -gt $ThresholdMB) {
    Write-Host "Reclaimable space exceeds threshold → ResetBase allowed."
    $RunResetBase = $true
}

# --- EXECUTE RESETBASE IF APPROVED ---
if ($RunResetBase) {
    Write-Host "Running StartComponentCleanup with ResetBase..."
    "=== StartComponentCleanup /ResetBase ===" | Out-File -Append $LogFile
    dism.exe /online /cleanup-image /StartComponentCleanup /ResetBase | Out-File -Append $LogFile
    Write-Host "ResetBase completed."
} else {
    Write-Host "ResetBase skipped (not recommended)."
    "=== ResetBase Skipped ===" | Out-File -Append $LogFile
}

Write-Host "Component Store maintenance finished."
"=== Completed ===" | Out-File -Append $LogFile
