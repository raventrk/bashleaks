# BashLeaks Windows Build Script
Write-Host "=== BashLeaks Build Starting ==="

# Check Go installation
$goVersion = (go version 2>$null)
if (-not $?) {
    Write-Host "Error: Go is not installed or not found in PATH!" -ForegroundColor Red
    Write-Host "Please download and install Go from https://golang.org/dl/" -ForegroundColor Yellow
    exit 1
}

Write-Host "Go version: $goVersion" -ForegroundColor Green

# Install required modules
Write-Host "Installing dependencies..."
go mod download
if (-not $?) {
    Write-Host "Error: Failed to download dependencies!" -ForegroundColor Red
    exit 1
}
Write-Host "Dependencies installed successfully." -ForegroundColor Green

# Build process
Write-Host "Building BashLeaks..."
go build -o bashleaks.exe cmd/bashleaks/main.go
if (-not $?) {
    Write-Host "Error: Build failed!" -ForegroundColor Red
    exit 1
}
Write-Host "BashLeaks built successfully: bashleaks.exe" -ForegroundColor Green

# Configure permissions
Write-Host "Configuring file permissions..."
icacls test.sh /grant Everyone:F
if (-not $?) {
    Write-Host "Warning: Could not set access permissions for test.sh." -ForegroundColor Yellow
    Write-Host "You may encounter access errors during scanning." -ForegroundColor Yellow
    Write-Host "Alternatively, you can add test.sh to the .bashleaksignore file." -ForegroundColor Yellow
}

# Check for .bashleaksignore file
if (-not (Test-Path .bashleaksignore)) {
    Write-Host "Creating .bashleaksignore file..."
    @"
# Files excluded from BashLeaks scanning
# For files causing access issues in Windows environment

# Exclude example test.sh
test.sh
"@ | Out-File -FilePath .bashleaksignore -Encoding utf8
    Write-Host ".bashleaksignore file created." -ForegroundColor Green
}

Write-Host "=== Build process completed! ===" -ForegroundColor Cyan
Write-Host "To run the program: .\bashleaks.exe <file_or_directory_to_scan>" -ForegroundColor Cyan 