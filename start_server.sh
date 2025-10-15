#!/bin/bash

# Define terminal colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Define path based on this file's location
SCRIPT_PATH="$(realpath "$0")"
SCRIPT_DIR="$(dirname "$SCRIPT_PATH")"
VENV_DIR="$SCRIPT_DIR/.venv"

echo -e "${GREEN}==================================="
echo "     SEPHOSTING SERVER LAUNCHER"
echo -e "===================================${NC}"
echo ""

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[ERROR] Python is not installed.${NC}"
    echo "Please install Python from https://www.python.org/downloads/"
    exit 1
fi

# Locate Python 3.11
if command -v python3.11 &> /dev/null; then
    echo -e "${GREEN}[SUCCESS] Python 3.11 exists!${NC}"
    PYTHON_BIN=$(command -v python3.11)
else
    PYTHON_BIN=$(command -v python3)
    PY_VER=$($PYTHON_BIN -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')
    echo -e "${RED}[ERROR] Python 3.11 is required, but found Python $PY_VER.${NC}"
    echo "Please install Python 3.11 from https://www.python.org/downloads/"
    exit 1
fi

# Create the virtual environment if it doesn't exist
if [ ! -d "$VENV_DIR/bin" ]; then
    echo -e "${YELLOW}[INFO] Creating virtual environment...${NC}"
    $PYTHON_BIN -m venv "$VENV_DIR"
else
    echo -e "${GREEN}[SUCCESS] Virtual already environment exists!${NC}"
fi

# Activate the virtual environment
echo -e "${YELLOW}[INFO] Activating virtual environment...${NC}"
if source "$VENV_DIR/bin/activate"; then
    echo -e "${GREEN}[SUCCESS] Activated virtual environment!${NC}"
else
    echo -e "${RED}[ERROR] Failed to activate virtual environment!${NC}"
    exit 1
fi

# Ensure that we are not using externally managed pip
echo -e "${YELLOW}[INFO] checking pip in virtual environment...${NC}"
if [ $(which pip) == "$VENV_DIR/bin/pip" ]; then
    echo -e "${GREEN}[SUCCESS] Using pip from virtual envirornment!"
else
    echo -e "${RED}[ERROR] Virtual environment does not have pip!${NC}"
    echo "Check python3.11-venv installation."
    exit 1
fi

# Check python version inside virtual environment
if command -v python3.11 &> /dev/null; then
    echo -e "${GREEN}[SUCCESS] Virtual environment is using Python 3.11!${NC}"
else
    PYTHON_BIN=$(command -v python3)
    PY_VER=$($PYTHON_BIN -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')
    PY_MAJOR_MINOR=$(echo "$PY_VER" | cut -d. -f1,2)
    echo -e "${RED}[ERROR] Python 3.11 is required, but found Python $PY_VER.${NC}"
    echo "Virtual environment needs to use Python 3.11"
    exit 1
fi

# Check if requirements.txt exists
if [ ! -f "requirements.txt" ]; then
    echo -e "${RED}[ERROR] requirements.txt not found!${NC}"
    exit 1
fi

# Check if dependencies are installed
echo -e "${YELLOW}[INFO] Checking dependencies...${NC}"
if python3 -c "import flask, flask_sqlalchemy, flask_login, werkzeug, humanize, flask_wtf" 2>/dev/null; then
    echo -e "${GREEN}[SUCCESS] All dependencies are already installed.${NC}"
else
    echo -e "${YELLOW}[INFO] Dependencies not found or incomplete. Installing from requirements.txt...${NC}"
    if pip3 install -r requirements.txt 2>/dev/null || pip install -r requirements.txt 2>/dev/null; then
        echo -e "${GREEN}[SUCCESS] Dependencies installed successfully!${NC}"
    else
        echo -e "${RED}[ERROR] Failed to install dependencies. Please check your internet connection.${NC}"
        exit 1
    fi
fi

# Check if app.py exists
if [ ! -f "app.py" ]; then
    echo -e "${RED}[ERROR] The file app.py does not exist in this directory.${NC}"
    exit 1
fi

# Create necessary directories
if [ ! -d "user_uploads" ]; then
    echo -e "${YELLOW}[INFO] Creating user_uploads directory...${NC}"
    mkdir user_uploads
fi

# Launch Flask server
echo ""
echo -e "${GREEN}[INFO] Starting Sephosting server...${NC}"
echo -e "${YELLOW}[INFO] Access the application in your browser: http://127.0.0.1:83${NC}"
echo -e "${YELLOW}[INFO] Press CTRL+C to stop the server${NC}"
echo ""
echo -e "${GREEN}[INFO] Default administrator credentials:${NC}"
echo "      Username: Admin"
echo "      Password: Admin"
echo "      (You will need to change these credentials on first login)"
echo ""
echo -e "${GREEN}==================================${NC}"
echo ""

# Run Flask application
sudo "$VENV_DIR/bin/python3" app.py || sudo "$VENV_DIR/bin/python" python app.py 
