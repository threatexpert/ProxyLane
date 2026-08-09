@echo off
setlocal

for %%I in ("%~dp0..") do set "PROXYLANE_ROOT=%%~fI"
cd /d "%PROXYLANE_ROOT%"

where rustup.exe >nul 2>&1
if errorlevel 1 (
    echo [ERROR] rustup.exe was not found in PATH.
    echo Install Rust from https://rustup.rs/ and select the MSVC toolchain.
    exit /b 1
)

where cargo.exe >nul 2>&1
if errorlevel 1 (
    echo [ERROR] cargo.exe was not found in PATH.
    echo Restart this command prompt after installing Rust.
    exit /b 1
)

echo Building ProxyLaneSecureTransport Release DLLs for Win32 and x64...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PROXYLANE_ROOT%\scripts\build-secure-transport.ps1"
if errorlevel 1 (
    echo.
    echo [ERROR] Secure transport build failed.
    exit /b 1
)

echo.
echo [OK] Release DLLs were written to:
echo   %PROXYLANE_ROOT%\bin\ProxyLaneSecureTransport32.dll
echo   %PROXYLANE_ROOT%\bin\ProxyLaneSecureTransport64.dll
exit /b 0
