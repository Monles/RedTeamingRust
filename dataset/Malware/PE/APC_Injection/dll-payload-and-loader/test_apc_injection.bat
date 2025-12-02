@echo off
REM ========================================
REM APC Injection DLL Loader Test Script
REM Educational Use Only
REM ========================================

cd /d "%~dp0"

echo ========================================
echo APC Injection DLL Loader Test
echo ========================================
echo.
echo [*] Test Location: %CD%
echo.

REM Setup directory structure
echo [*] Setting up directory structure...
if not exist "target\release" mkdir target\release
copy /Y payload_dll_windows_x86_64_release.dll target\release\payload_dll.dll >nul 2>&1
if %errorlevel% neq 0 (
    echo [-] ERROR: Failed to copy DLL to target directory
    pause
    exit /b 1
)
echo [+] DLL copied to target\release\payload_dll.dll

echo.
echo ========================================
echo Test 1: Release Build
echo ========================================
echo [*] Running dll_loader_windows_x86_64_release.exe
echo.

dll_loader_windows_x86_64_release.exe
set RELEASE_EXIT=%errorlevel%

echo.
echo [*] Loader exit code: %RELEASE_EXIT%

REM Wait a moment for Notepad to launch
timeout /t 2 /nobreak >nul

echo.
echo [*] Checking if Notepad launched...
tasklist /FI "IMAGENAME eq notepad.exe" 2>NUL | find /I /N "notepad.exe">NUL
if "%errorlevel%"=="0" (
    echo [+] SUCCESS: Notepad.exe is running!
    echo.
    echo [*] Notepad processes:
    tasklist /FI "IMAGENAME eq notepad.exe"
    set TEST1=PASSED
) else (
    echo [-] FAILED: Notepad.exe not found
    set TEST1=FAILED
)

echo.
echo ========================================
echo Test 2: Debug Build
echo ========================================
echo [*] Running dll_loader_windows_x86_64_debug.exe
echo.

REM Copy DLL for debug build as well
copy /Y payload_dll_windows_x86_64_debug.dll target\release\payload_dll.dll >nul 2>&1

dll_loader_windows_x86_64_debug.exe
set DEBUG_EXIT=%errorlevel%

echo.
echo [*] Loader exit code: %DEBUG_EXIT%

REM Wait a moment for Notepad to launch
timeout /t 2 /nobreak >nul

echo.
echo [*] Checking if Notepad launched...
tasklist /FI "IMAGENAME eq notepad.exe" 2>NUL | find /I /N "notepad.exe">NUL
if "%errorlevel%"=="0" (
    echo [+] SUCCESS: Notepad.exe is running!
    set TEST2=PASSED
) else (
    echo [-] FAILED: Notepad.exe not found
    set TEST2=FAILED
)

echo.
echo ========================================
echo Test 3: Manual DLL Invocation
echo ========================================
echo [*] Testing DLL directly with rundll32...
echo.

rundll32.exe payload_dll_windows_x86_64_release.dll,run

timeout /t 2 /nobreak >nul

tasklist /FI "IMAGENAME eq notepad.exe" 2>NUL | find /I /N "notepad.exe">NUL
if "%errorlevel%"=="0" (
    echo [+] SUCCESS: Direct DLL invocation works!
    set TEST3=PASSED
) else (
    echo [-] FAILED: Direct DLL invocation failed
    set TEST3=FAILED
)

echo.
echo ========================================
echo Test Summary
echo ========================================
echo Test 1 (Release Build): %TEST1%
echo Test 2 (Debug Build):   %TEST2%
echo Test 3 (Direct DLL):    %TEST3%
echo.

if "%TEST1%"=="PASSED" (
    echo [+] Overall Status: PASS
    echo [+] APC Injection DLL technique verified successfully
    echo.
    echo [*] Note: Multiple Notepad windows may be open from testing
    echo [*] You can close them manually or run: taskkill /IM notepad.exe /F
) else (
    echo [-] Overall Status: FAIL
    echo [-] Review error messages above
)

echo.
echo ========================================
echo Cleanup
echo ========================================
echo.
choice /C YN /M "Do you want to kill all Notepad processes"
if errorlevel 2 goto :skip_cleanup
if errorlevel 1 goto :do_cleanup

:do_cleanup
echo [*] Killing Notepad processes...
taskkill /IM notepad.exe /F >nul 2>&1
echo [+] Cleanup complete
goto :end

:skip_cleanup
echo [*] Skipping cleanup

:end
echo.
pause
