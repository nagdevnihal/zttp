#!/bin/bash
set -e

# ZTTP Multi-Platform Installer Script

SERVER_URL="http://localhost" # Will be updated during deployment
DEFAULT_PORT=2224

echo "=== ZTTP CLI Installer ==="
OS="$(uname -s)"
ARCH="$(uname -m)"

# Normalize architecture
if [ "$ARCH" = "x86_64" ]; then
    ARCH="amd64"
elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
    ARCH="arm64"
else
    echo "✗ Unsupported architecture: $ARCH"
    exit 1
fi

check_port() {
    if ss -tlnp 2>/dev/null | grep -q ":$1 "; then
        return 1
    fi
    return 0
}

download_binary() {
    local target_os=$1
    local binary_name="zttp-${target_os}-${ARCH}"
    local download_url="${SERVER_URL}/dist/release/${binary_name}"
    
    echo "Downloading ${binary_name}..."
    if ! curl -fSL "$download_url" -o /tmp/zttp; then
        echo "✗ Failed to download binary from $download_url"
        exit 1
    fi
    chmod +x /tmp/zttp
}

# ---------------------------------------------------------
# Windows
# ---------------------------------------------------------
if [[ "$OS" == *"MINGW"* ]] || [[ "$OS" == *"CYGWIN"* ]] || [[ "$OS" == *"MSYS"* ]]; then
    echo "This script does not support Windows natively."
    echo "Please download and run the PowerShell installer:"
    echo "  1. Download: ${SERVER_URL}/install.ps1"
    echo "  2. Open PowerShell as Administrator"
    echo "  3. Run: Set-ExecutionPolicy RemoteSigned -Scope CurrentUser"
    echo "  4. Run: .\install.ps1"
    exit 1
fi

# ---------------------------------------------------------
# macOS
# ---------------------------------------------------------
if [ "$OS" = "Darwin" ]; then
    echo "Detected: macOS ($ARCH)"
    download_binary "darwin"
    
    echo "Installing to /usr/local/bin/zttp..."
    sudo mv /tmp/zttp /usr/local/bin/zttp
    
    # Strip quarantine flag to bypass Gatekeeper warning
    xattr -d com.apple.quarantine /usr/local/bin/zttp 2>/dev/null || true
    
    echo "✓ Installed successfully! Type 'zttp' to connect."
    exit 0
fi

# ---------------------------------------------------------
# Linux
# ---------------------------------------------------------
if [ "$OS" = "Linux" ]; then
    echo "Detected: Linux ($ARCH)"
    echo ""
    echo "How would you like to install ZTTP?"
    echo "  1) Systemd Service   (starts on boot, auto-restarts)"
    echo "  2) Docker Container  (requires Docker installed)"
    echo "  3) Plain Executable  (just copy to /usr/local/bin)"
    echo ""
    read -p "Enter choice [1/2/3]: " CHOICE < /dev/tty

    if [ "$CHOICE" = "1" ] || [ "$CHOICE" = "2" ]; then
        if ! check_port $DEFAULT_PORT; then
            echo "⚠ Port $DEFAULT_PORT is already in use."
            read -p "Enter an alternative local port to bind: " USER_PORT < /dev/tty
            if ! check_port "$USER_PORT"; then
                echo "✗ Port $USER_PORT is also in use. Cannot proceed."
                exit 1
            fi
            PORT=$USER_PORT
        else
            PORT=$DEFAULT_PORT
        fi
    fi

    download_binary "linux"

    if [ "$CHOICE" = "1" ]; then
        echo "Installing as systemd service..."
        sudo mv /tmp/zttp /usr/local/bin/zttp
        
        cat <<EOF | sudo tee /etc/systemd/system/zttp.service > /dev/null
[Unit]
Description=ZTTP Secure Proxy Client
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/zttp
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
        sudo systemctl daemon-reload
        sudo systemctl enable zttp
        sudo systemctl start zttp
        echo "✓ ZTTP service running. Type 'zttp' to connect."

    elif [ "$CHOICE" = "2" ]; then
        echo "Installing as Docker container..."
        if ! command -v docker &> /dev/null; then
            echo "✗ Docker is not installed. Please install Docker or choose another option."
            exit 1
        fi
        
        sudo mkdir -p /etc/zttp
        sudo mv /tmp/zttp /etc/zttp/zttp
        
        cat <<EOF | sudo tee /etc/zttp/Dockerfile > /dev/null
FROM ubuntu:22.04
COPY zttp /usr/local/bin/zttp
ENTRYPOINT ["/usr/local/bin/zttp"]
EOF

        cat <<EOF | sudo tee /etc/zttp/docker-compose.yml > /dev/null
services:
  zttp-client:
    build: .
    container_name: zttp-client
    restart: unless-stopped
    stdin_open: true
    tty: true
EOF
        
        cd /etc/zttp
        sudo docker compose up -d --build
        
        # Add alias
        for rc in ~/.bashrc ~/.zshrc; do
            if [ -f "$rc" ]; then
                echo "alias zttp='docker exec -it zttp-client zttp'" >> "$rc"
            fi
        done
        
        echo "✓ Container running. Restart your terminal, then type 'zttp'."

    elif [ "$CHOICE" = "3" ]; then
        echo "Installing as plain executable..."
        sudo mv /tmp/zttp /usr/local/bin/zttp
        echo "✓ Installed. Type 'zttp' to connect."
    else
        echo "✗ Invalid choice."
        exit 1
    fi
fi
