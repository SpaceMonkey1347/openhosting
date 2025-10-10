#!/bin/bash

# Define terminal colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

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
python3 app.py || python app.py 