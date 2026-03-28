#!/bin/bash
# PrivAudit Build Script

set -e

echo "========================================="
echo "  PrivAudit - Build Script"
echo "========================================="

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check Python
echo -e "${YELLOW}[1/4] Checking Python...${NC}"
python3 --version
echo -e "${GREEN}✓ Python OK${NC}"

# Install dependencies
echo -e "${YELLOW}[2/4] Installing dependencies...${NC}"
pip install -r requirements.txt
pip install pyinstaller
echo -e "${GREEN}✓ Dependencies installed${NC}"

# Clean previous builds
echo -e "${YELLOW}[3/4] Cleaning previous builds...${NC}"
rm -rf build/ dist/ *.spec
echo -e "${GREEN}✓ Cleaned${NC}"

# Build with PyInstaller
echo -e "${YELLOW}[4/4] Building executable...${NC}"
pyinstaller \
    --onefile \
    --name priv-audit \
    --console \
    --add-data "README.md:." \
    --add-data "requirements.txt:." \
    --hidden-import colorama \
    --hidden-import psutil \
    --hidden-import yaml \
    --hidden-import tabulate \
    --clean \
    main.py
echo -e "${GREEN}✓ Build complete${NC}"

# Show result
echo ""
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}  Build Successful!${NC}"
echo -e "${GREEN}=========================================${NC}"
echo ""
echo "Executable: dist/priv-audit"
echo "Size: $(ls -lh dist/priv-audit | awk '{print $5}')"
echo ""
echo "To test:"
echo "  ./dist/priv-audit --help"
echo "  sudo ./dist/priv-audit --full"
