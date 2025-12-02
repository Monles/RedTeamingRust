# ========================================
# APC Injection DLL Loader Test Script
# PowerShell Version with Enhanced Monitoring
# Educational Use Only
# ========================================

$ErrorActionPreference = "Continue"
$TestDir = $PSScriptRoot
Set-Location $TestDir

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "APC Injection DLL Loader Test" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "[*] Test Location: $TestDir"
Write-Host ""

# Setup directory structure
Write-Host "[*] Setting up directory structure..." -ForegroundColor Yellow
$targetDir = Join-Path $TestDir "target\release"
if (-not (Test-Path $targetDir)) {
    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
}

$sourceDll = Join-Path $TestDir "payload_dll_windows_x86_64_release.dll"
$targetDll = Join-Path $targetDir "payload_dll.dll"

if (Test-Path $sourceDll) {
    Copy-Item $sourceDll $targetDll -Force
    Write-Host "[+] DLL copied to target\release\payload_dll.dll" -ForegroundColor Green
} else {
    Write-Host "[-] ERROR: Source DLL not found: $sourceDll" -ForegroundColor Red
    pause
    exit 1
}

# Get baseline notepad count
$baselineNotepadCount = @(Get-Process -Name notepad -ErrorAction SilentlyContinue).Count
Write-Host "[*] Baseline Notepad processes: $baselineNotepadCount"
Write-Host ""

# Test 1: Release Build
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test 1: Release Build" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "[*] Running dll_loader_windows_x86_64_release.exe"
Write-Host ""

$releaseLoader = Join-Path $TestDir "dll_loader_windows_x86_64_release.exe"
if (Test-Path $releaseLoader) {
    $releaseProcess = Start-Process -FilePath $releaseLoader -NoNewWindow -PassThru -Wait
    $releaseExitCode = $releaseProcess.ExitCode
    Write-Host "[*] Loader exit code: $releaseExitCode"

    Start-Sleep -Seconds 2

    $notepadProcesses = @(Get-Process -Name notepad -ErrorAction SilentlyContinue)
    $newNotepadCount = $notepadProcesses.Count

    if ($newNotepadCount -gt $baselineNotepadCount) {
        Write-Host "[+] SUCCESS: Notepad.exe launched!" -ForegroundColor Green
        Write-Host "[*] New Notepad processes: $($newNotepadCount - $baselineNotepadCount)"
        $test1Result = "PASSED"

        # Show details of new Notepad processes
        $notepadProcesses | Select-Object Id, ProcessName, StartTime, @{Name='Memory(MB)';Expression={[math]::Round($_.WorkingSet64/1MB,2)}} | Format-Table
    } else {
        Write-Host "[-] FAILED: Notepad.exe not launched" -ForegroundColor Red
        $test1Result = "FAILED"
    }
} else {
    Write-Host "[-] ERROR: Release loader not found: $releaseLoader" -ForegroundColor Red
    $test1Result = "FAILED"
}

Write-Host ""

# Test 2: Debug Build
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test 2: Debug Build" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "[*] Running dll_loader_windows_x86_64_debug.exe"
Write-Host ""

$baselineNotepadCount = @(Get-Process -Name notepad -ErrorAction SilentlyContinue).Count

$sourceDllDebug = Join-Path $TestDir "payload_dll_windows_x86_64_debug.dll"
if (Test-Path $sourceDllDebug) {
    Copy-Item $sourceDllDebug $targetDll -Force
}

$debugLoader = Join-Path $TestDir "dll_loader_windows_x86_64_debug.exe"
if (Test-Path $debugLoader) {
    $debugProcess = Start-Process -FilePath $debugLoader -NoNewWindow -PassThru -Wait
    $debugExitCode = $debugProcess.ExitCode
    Write-Host "[*] Loader exit code: $debugExitCode"

    Start-Sleep -Seconds 2

    $newNotepadCount = @(Get-Process -Name notepad -ErrorAction SilentlyContinue).Count

    if ($newNotepadCount -gt $baselineNotepadCount) {
        Write-Host "[+] SUCCESS: Notepad.exe launched!" -ForegroundColor Green
        $test2Result = "PASSED"
    } else {
        Write-Host "[-] FAILED: Notepad.exe not launched" -ForegroundColor Red
        $test2Result = "FAILED"
    }
} else {
    Write-Host "[-] ERROR: Debug loader not found: $debugLoader" -ForegroundColor Red
    $test2Result = "FAILED"
}

Write-Host ""

# Test 3: Direct DLL Invocation
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test 3: Manual DLL Invocation" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "[*] Testing DLL directly with rundll32..."
Write-Host ""

$baselineNotepadCount = @(Get-Process -Name notepad -ErrorAction SilentlyContinue).Count

# Restore release DLL
Copy-Item $sourceDll $targetDll -Force

$rundll32Args = "$sourceDll,run"
Start-Process -FilePath "rundll32.exe" -ArgumentList $rundll32Args -NoNewWindow -Wait

Start-Sleep -Seconds 2

$newNotepadCount = @(Get-Process -Name notepad -ErrorAction SilentlyContinue).Count

if ($newNotepadCount -gt $baselineNotepadCount) {
    Write-Host "[+] SUCCESS: Direct DLL invocation works!" -ForegroundColor Green
    $test3Result = "PASSED"
} else {
    Write-Host "[-] FAILED: Direct DLL invocation failed" -ForegroundColor Red
    $test3Result = "FAILED"
}

Write-Host ""

# Summary
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$results = @(
    [PSCustomObject]@{Test="Test 1 (Release Build)"; Result=$test1Result},
    [PSCustomObject]@{Test="Test 2 (Debug Build)"; Result=$test2Result},
    [PSCustomObject]@{Test="Test 3 (Direct DLL)"; Result=$test3Result}
)

$results | Format-Table -AutoSize

if ($test1Result -eq "PASSED") {
    Write-Host "[+] Overall Status: PASS" -ForegroundColor Green
    Write-Host "[+] APC Injection DLL technique verified successfully" -ForegroundColor Green
    Write-Host ""
    Write-Host "[*] Note: Multiple Notepad windows may be open from testing" -ForegroundColor Yellow
} else {
    Write-Host "[-] Overall Status: FAIL" -ForegroundColor Red
    Write-Host "[-] Review error messages above" -ForegroundColor Red
}

Write-Host ""

# Process Information
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Current Notepad Processes" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
$notepadProcesses = Get-Process -Name notepad -ErrorAction SilentlyContinue
if ($notepadProcesses) {
    $notepadProcesses | Select-Object Id, ProcessName, StartTime, @{Name='Memory(MB)';Expression={[math]::Round($_.WorkingSet64/1MB,2)}} | Format-Table
} else {
    Write-Host "[*] No Notepad processes running"
}

Write-Host ""

# Cleanup option
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Cleanup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$cleanup = Read-Host "Do you want to kill all Notepad processes? (Y/N)"
if ($cleanup -eq "Y" -or $cleanup -eq "y") {
    Write-Host "[*] Killing Notepad processes..." -ForegroundColor Yellow
    Get-Process -Name notepad -ErrorAction SilentlyContinue | Stop-Process -Force
    Write-Host "[+] Cleanup complete" -ForegroundColor Green
} else {
    Write-Host "[*] Skipping cleanup" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
