# npm-safe Installation Script for Windows (PowerShell)
# Robust installation with detection, update, and uninstall options

param(
    [switch]$Uninstall,
    [switch]$Help
)

$ErrorActionPreference = "Stop"

$FIREWALL_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$BIN_DIR = Join-Path $FIREWALL_DIR "bin"
$MARKER_START = "# npm-safe - START"
$MARKER_END = "# npm-safe - END"

# PowerShell profile path
$PROFILE_PATH = $PROFILE.CurrentUserAllHosts
if (-not $PROFILE_PATH) {
    $PROFILE_PATH = $PROFILE
}

function Print-Header {
    param([string]$Message)
    Write-Host ""
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host "   $Message" -ForegroundColor Cyan
    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Print-Ok {
    param([string]$Message)
    Write-Host "[OK] " -ForegroundColor Green -NoNewline
    Write-Host $Message
}

function Print-Skip {
    param([string]$Message)
    Write-Host "[SKIP] " -ForegroundColor Yellow -NoNewline
    Write-Host $Message
}

function Print-Error {
    param([string]$Message)
    Write-Host "[ERROR] " -ForegroundColor Red -NoNewline
    Write-Host $Message
}

function Is-Installed {
    param([string]$FilePath)
    
    if (Test-Path $FilePath) {
        $content = Get-Content $FilePath -Raw -ErrorAction SilentlyContinue
        return $content -match [regex]::Escape($MARKER_START)
    }
    return $false
}

function Remove-FromFile {
    param([string]$FilePath)
    
    if (Test-Path $FilePath) {
        if (Is-Installed $FilePath) {
            $content = Get-Content $FilePath -Raw
            $pattern = "(?s)$([regex]::Escape($MARKER_START)).*?$([regex]::Escape($MARKER_END))\r?\n?"
            $newContent = $content -replace $pattern, ""
            Set-Content -Path $FilePath -Value $newContent -NoNewline
            return $true
        }
    }
    return $false
}

function Add-ToFile {
    param([string]$FilePath)
    
    $fileName = Split-Path $FilePath -Leaf
    
    # Create profile if it doesn't exist
    if (-not (Test-Path $FilePath)) {
        $profileDir = Split-Path $FilePath -Parent
        if (-not (Test-Path $profileDir)) {
            New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
        }
        New-Item -ItemType File -Path $FilePath -Force | Out-Null
        Print-Ok "Created $fileName"
    }
    
    Write-Host "Processing $fileName..."
    
    # Check if already installed
    if (Is-Installed $FilePath) {
        $content = Get-Content $FilePath -Raw
        if ($content -match [regex]::Escape($BIN_DIR)) {
            Print-Skip "Already installed in $fileName with correct path"
        } else {
            Print-Error "Installed but path is outdated in $fileName"
            Write-Host "  Updating installation..."
            Remove-FromFile $FilePath
            Add-ToFile $FilePath
        }
        return
    }
    
    # Add installation
    $installBlock = @"

$MARKER_START
`$env:PATH = "$BIN_DIR;`$env:PATH"
function npm-safe { & "$BIN_DIR\npm-safe" @args }
function firewall-config { & "$BIN_DIR\firewall-config" @args }
$MARKER_END
"@
    
    Add-Content -Path $FilePath -Value $installBlock
    Print-Ok "Added to $fileName"
}

function Uninstall-Firewall {
    Print-Header "Node Firewall Uninstallation"
    
    $removed = $false
    
    # Remove from PowerShell profile
    if (Remove-FromFile $PROFILE_PATH) {
        Print-Ok "Removed from PowerShell profile"
        $removed = $true
    }
    
    # Remove from PATH (User environment variable)
    try {
        $userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
        if ($userPath -match [regex]::Escape($BIN_DIR)) {
            $newPath = ($userPath -split ';' | Where-Object { $_ -ne $BIN_DIR }) -join ';'
            [Environment]::SetEnvironmentVariable("PATH", $newPath, "User")
            Print-Ok "Removed from User PATH"
            $removed = $true
        }
    } catch {
        Print-Skip "Could not check User PATH"
    }
    
    if (-not $removed) {
        Print-Skip "No installation found"
    } else {
        Write-Host ""
        Print-Ok "Uninstallation complete!"
        Write-Host ""
        Write-Host "To complete removal:"
        Write-Host "  1. Restart PowerShell or run: . `$PROFILE"
        Write-Host "  2. Optionally delete this directory"
    }
    
    exit 0
}

function Install-Firewall {
    Print-Header "Node Firewall Installation"
    
    # Verify required files exist
    $npmSafePath = Join-Path $BIN_DIR "npm-safe"
    $configPath = Join-Path $BIN_DIR "firewall-config"
    
    if (-not (Test-Path $npmSafePath)) {
        Print-Error "npm-safe not found in $BIN_DIR"
        exit 1
    }
    
    if (-not (Test-Path $configPath)) {
        Print-Error "firewall-config not found in $BIN_DIR"
        exit 1
    }
    
    # Add to PowerShell profile
    Add-ToFile $PROFILE_PATH
    
    # Add to User PATH environment variable (persistent)
    try {
        $userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
        if (-not ($userPath -match [regex]::Escape($BIN_DIR))) {
            $newPath = "$BIN_DIR;$userPath"
            [Environment]::SetEnvironmentVariable("PATH", $newPath, "User")
            Print-Ok "Added to User PATH environment variable"
        } else {
            Print-Skip "Already in User PATH"
        }
    } catch {
        Print-Skip "Could not update User PATH (requires admin)"
    }
    
    Write-Host ""
    Print-Header "Installation Complete!"
    
    Write-Host "Next steps:"
    Write-Host "  1. Reload your PowerShell profile:"
    Write-Host "     " -NoNewline
    Write-Host ". `$PROFILE" -ForegroundColor Green
    Write-Host ""
    Write-Host "  2. Initialize firewall config:"
    Write-Host "     " -NoNewline
    Write-Host "firewall-config init" -ForegroundColor Green
    Write-Host ""
    Write-Host "  3. Install packages safely:"
    Write-Host "     " -NoNewline
    Write-Host "npm-safe install" -ForegroundColor Green
    Write-Host ""
    Write-Host "To uninstall: " -NoNewline
    Write-Host ".\install.ps1 -Uninstall" -ForegroundColor Green
    Write-Host ""
}

function Show-Help {
    Write-Host "Node Firewall Installation Script for Windows"
    Write-Host ""
    Write-Host "Usage:"
    Write-Host "  .\install.ps1              Install or update"
    Write-Host "  .\install.ps1 -Uninstall   Remove installation"
    Write-Host "  .\install.ps1 -Help        Show this help"
    Write-Host ""
    exit 0
}

# Main
if ($Help) {
    Show-Help
} elseif ($Uninstall) {
    Uninstall-Firewall
} else {
    Install-Firewall
}
