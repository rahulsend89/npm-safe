@echo off
REM npm-safe Installation Script for Windows (CMD/Batch)
REM This is a simple wrapper that calls the PowerShell script

setlocal

REM Check if PowerShell is available
where pwsh >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo Using PowerShell Core...
    pwsh -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
    goto :end
)

where powershell >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo Using Windows PowerShell...
    powershell -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
    goto :end
)

echo ERROR: PowerShell is not available on this system.
echo Please install PowerShell or use install.ps1 directly.
exit /b 1

:end
endlocal
