#!/bin/bash

# Spectrum Hawk Run Script
# Run with: sudo ./run.sh

if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root: sudo $0"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PYTHON="$SCRIPT_DIR/shawk-venv/bin/python"
MAIN_SCRIPT="$SCRIPT_DIR/spectrum_hawk.py"

if [ ! -f "$VENV_PYTHON" ]; then
    echo "Virtual environment not found. Please run setup.sh first."
    exit 1
fi

if [ ! -f "$MAIN_SCRIPT" ]; then
    echo "Main script not found: $MAIN_SCRIPT"
    exit 1
fi

"$VENV_PYTHON" "$MAIN_SCRIPT"
