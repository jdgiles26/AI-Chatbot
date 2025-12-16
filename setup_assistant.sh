#!/bin/bash
# Setup script for Mac Mini M2 Security Assistant

echo "==================================================================="
echo "Mac Mini M2 Security Assistant - Installation"
echo "==================================================================="
echo ""

# Check if running on macOS
if [[ "$(uname)" != "Darwin" ]]; then
    echo "WARNING: This tool is optimized for macOS (Mac Mini M2)"
    echo "Some features may not work correctly on other platforms."
    echo ""
fi

# Check Python version
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "Detected Python version: $python_version"

# Check if Python 3.8+ is available
if python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)'; then
    echo "✓ Python version is compatible"
else
    echo "✗ Python 3.8 or higher is required"
    exit 1
fi

echo ""
echo "Installing dependencies..."

# Install Python dependencies if requirements.txt has actual packages
if grep -v '^#' assistant/requirements.txt | grep -v '^$' | grep -q '[^[:space:]]'; then
    pip3 install -r assistant/requirements.txt
    if [ $? -eq 0 ]; then
        echo "✓ Dependencies installed successfully"
    else
        echo "✗ Failed to install dependencies"
        exit 1
    fi
else
    echo "✓ No additional dependencies required"
fi

# Make CLI executable
chmod +x assistant/cli.py
echo "✓ Made CLI executable"

echo ""
echo "==================================================================="
echo "Installation Complete!"
echo "==================================================================="
echo ""
echo "You can now use the security assistant:"
echo ""
echo "  Basic scan:"
echo "    python3 assistant/cli.py scan --path /Users"
echo ""
echo "  Generate report:"
echo "    python3 assistant/cli.py scan --path /Users --output report.json"
echo ""
echo "  Start monitoring:"
echo "    python3 assistant/cli.py monitor --path /Users --interval 300"
echo ""
echo "  Get help:"
echo "    python3 assistant/cli.py --help"
echo ""
echo "==================================================================="
