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

# Install required dependencies
echo -e "${YELLOW}[INFO] Installing dependencies...${NC}"
pip3 install flask flask-sqlalchemy flask-login werkzeug humanize || pip install flask flask-sqlalchemy flask-login werkzeug humanize

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