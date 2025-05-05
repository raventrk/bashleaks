#!/bin/bash

echo "=== BashLeaks Build Starting ==="

# Check Go installation
if ! command -v go &> /dev/null; then
    echo -e "\033[31mError: Go is not installed or not found in PATH!\033[0m"
    echo -e "\033[33mPlease download and install Go from https://golang.org/dl/\033[0m"
    exit 1
fi

echo -e "\033[32mGo version: $(go version)\033[0m"

# Install required modules
echo "Installing dependencies..."
go mod download
if [ $? -ne 0 ]; then
    echo -e "\033[31mError: Failed to download dependencies!\033[0m"
    exit 1
fi
echo -e "\033[32mDependencies installed successfully.\033[0m"

# Build process
echo "Building BashLeaks..."
GOOS=$(uname -s | tr '[:upper:]' '[:lower:]')
GOARCH=$(uname -m)
if [ "$GOARCH" = "x86_64" ]; then
    GOARCH="amd64"
elif [ "$GOARCH" = "aarch64" ]; then
    GOARCH="arm64"
fi

go build -o bashleaks cmd/bashleaks/main.go
if [ $? -ne 0 ]; then
    echo -e "\033[31mError: Build failed!\033[0m"
    exit 1
fi
echo -e "\033[32mBashLeaks built successfully: bashleaks\033[0m"

# Configure permissions
echo "Configuring file permissions..."
chmod +x bashleaks
chmod +x test.sh

# Check for .bashleaksignore file
if [ ! -f .bashleaksignore ]; then
    echo "Creating .bashleaksignore file..."
    cat > .bashleaksignore << EOF
# Files excluded from BashLeaks scanning
# For files causing access issues

# Add files here if needed
EOF
    echo -e "\033[32m.bashleaksignore file created.\033[0m"
fi

echo -e "\033[36m=== Build process completed! ===\033[0m"
echo -e "\033[36mTo run the program: ./bashleaks <file_or_directory_to_scan>\033[0m" 