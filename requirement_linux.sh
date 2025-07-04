#!/usr/bin/env bash
# requirement_linux.sh — setup for TAMAL‑STEGO on Debian/Ubuntu

set -e

echo "==> Updating apt package lists..."
sudo apt update

echo "==> Installing Python 3, pip, and build tools..."
sudo apt install -y python3 python3-pip python3-venv build-essential

echo "==> Upgrading pip..."
python3 -m pip install --upgrade pip --break-system-packages

echo "==> Installing Python dependencies..."
python3 -m pip install pillow cryptography --upgrade --break-system-packages

echo "==> Attempting to install pqcrypto-lite (post-quantum Kyber support)..."
if python3 -m pip install pqcrypto-lite --upgrade --break-system-packages; then
    echo "✅ pqcrypto-lite installed successfully (Kyber enabled)."
else
    echo "⚠️  pqcrypto-lite could not be installed — post-quantum features will be disabled."
fi

echo "✅ All dependencies installed. You can now run:"
echo "   python3 tamal_stego.py -h"
