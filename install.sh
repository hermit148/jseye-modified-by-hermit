#!/bin/bash

# JSEye Automated Installation Script (Modified by H3RM!T)
# Colors for fancy terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'
NC_BOLD='\033[1m'

echo -e "${BLUE}================================================================${NC}"
echo -e "${BLUE}        JSEye Installation Assistant (Modified by H3RM!T)       ${NC}"
echo -e "${BLUE}================================================================${NC}"

# Check Python3 version
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}[-] Error: Python3 is not installed on this system.${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo -e "${GREEN}[+] Found Python version: ${PYTHON_VERSION}${NC}"

# Check Go version (recommended for transparent binary installer check)
if ! command -v go &>/dev/null; then
    echo -e "${YELLOW}[!] Warning: Go is not installed. Some external Go modules might not be compiled automatically.${NC}"
fi

# Step 1: Install Python dependencies and package
echo -e "${BLUE}[*] Installing python package and requirements...${NC}"
python3 -m pip install --upgrade pip
python3 -m pip install .

if [ $? -ne 0 ]; then
    echo -e "${RED}[-] Error: Failed to install python dependencies. Trying with --break-system-packages if on newer Linux distro...${NC}"
    python3 -m pip install . --break-system-packages
    if [ $? -ne 0 ]; then
         echo -e "${RED}[-] Fatal: Pip installation failed.${NC}"
         exit 1
    fi
fi

# Step 2: Install Playwright Chromium dependencies
echo -e "${BLUE}[*] Initializing Playwright browser environment...${NC}"
python3 -m playwright install chromium

if [ $? -ne 0 ]; then
    echo -e "${YELLOW}[!] Warning: Playwright browser installation encountered a problem. Trying to install system dependencies...${NC}"
    python3 -m playwright install-deps chromium
    python3 -m playwright install chromium
fi

echo -e "${GREEN}================================================================${NC}"
echo -e "${GREEN}[+] JSEye (Modified by H3RM!T) has been installed successfully!${NC}"
echo -e "${GREEN}================================================================${NC}"
echo -e "${YELLOW}You can now run: ${NC_BOLD}jseye --help${NC}"
