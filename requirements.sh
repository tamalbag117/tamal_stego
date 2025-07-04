#!/usr/bin/env bash
# requirements.sh — quick installer for TAMAL‑STEGO dependencies
# Works on Debian/Ubuntu, Fedora, Arch, or generic Linux with pip.
# Post‑quantum support (Kyber) requires Linux/macOS; Windows users should install
# only Pillow & cryptography via pip.

set -e

echo "==> Detecting package manager…"
if command -v apt-get >/dev/null; then
    PM="apt-get"
    PKGS="python3 python3-pip python3-venv build-essential"
elif command -v dnf >/dev/null; then
    PM="dnf"
    PKGS="python3 python3-pip python3-virtualenv gcc"
elif command -v pacman >/dev/null; then
    PM="pacman"
    PKGS="python python-pip base-devel"
else
    echo "Could not detect supported package manager. Please install Python 3, pip, Pillow, cryptography, and pqcrypto-lite manually."
    exit 1
fi

echo "==> Updating package lists…"
sudo $PM update -y || sudo $PM -Sy

echo "==> Installing system packages ($PKGS)…"
if [ "$PM" = "pacman" ]; then
    sudo $PM -S --noconfirm $PKGS
else
    sudo $PM install -y $PKGS
fi

echo "==> Upgrading pip…"
python3 -m pip install --upgrade pip

echo "==> Installing Python dependencies (Pillow, cryptography)…"
python3 -m pip install pillow cryptography --upgrade

echo "==> Attempting to install pqcrypto-lite for post‑quantum Kyber support…"
if python3 -m pip install pqcrypto-lite --upgrade; then
    echo "pqcrypto-lite installed successfully (Kyber enabled)."
else
    echo "pqcrypto-lite could not be installed on this platform. Kyber features will be disabled."
fi

echo "==> All done! You can now run:"
echo "    python tamal_stego.py -h"
