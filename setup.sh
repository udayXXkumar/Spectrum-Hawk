#!/bin/bash

# Spectrum Hawk Setup Script
# Run with: chmod +x setup.sh && sudo ./setup.sh

set -e

echo "========================================="
echo "   Spectrum Hawk 🦅 - Setup Script"
echo "========================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (sudo ./setup.sh)"
    exit 1
fi

echo "[+] Checking system dependencies..."

# Check for required system packages
REQUIRED_PKGS="aircrack-ng wireless-tools"

for pkg in $REQUIRED_PKGS; do
    if ! dpkg -l | grep -q "^ii  $pkg "; then
        echo "[*] Installing $pkg..."
        apt-get update && apt-get install -y $pkg
    fi
done

echo "[✓] System dependencies checked"

echo "[+] Setting up Python virtual environment..."

# Create virtual environment if it doesn't exist
if [ ! -d "shawk-venv" ]; then
    python3 -m venv shawk-venv
    echo "[✓] Virtual environment created: shawk-venv"
fi

# Create requirements.txt if it doesn't exist
if [ ! -f "requirements.txt" ]; then
    cat > requirements.txt << EOF
rich>=13.0.0
requests>=2.31.0
jinja2>=3.1.0
mac-vendor-lookup>=0.1.11
EOF
    echo "[✓] Created requirements.txt"
fi

# Install Python dependencies
echo "[*] Installing Python dependencies..."
./shawk-venv/bin/python -m pip install --upgrade pip
./shawk-venv/bin/python -m pip install -r requirements.txt

echo "[✓] Python dependencies installed"

# Make main script executable
chmod +x spectrum_hawk.py

echo ""
echo "========================================="
echo "   Setup Complete! 🎉"
echo "========================================="
echo ""
echo "To run Spectrum Hawk, use:"
echo "  sudo ./shawk-venv/bin/python spectrum_hawk.py"
echo ""
echo "Or create an alias in your shell:"
echo "  alias spectrum-hawk='sudo $(pwd)/shawk-venv/bin/python $(pwd)/spectrum_hawk.py'"
echo ""
echo "Happy scanning! 🦅"
