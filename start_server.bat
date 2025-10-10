@echo off
TITLE Sephosting Server
COLOR 0A

ECHO ===================================
ECHO      SEPHOSTING SERVER LAUNCHER
ECHO ===================================
ECHO.

:: Check if Python is installed
python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    ECHO [ERROR] Python is not installed or not in PATH.
    ECHO Please install Python from https://www.python.org/downloads/
    PAUSE
    EXIT /B 1
)

:: Check if requirements.txt exists
IF NOT EXIST requirements.txt (
    ECHO [ERROR] requirements.txt not found!
    PAUSE
    EXIT /B 1
)

:: Check if dependencies are installed
ECHO [INFO] Checking dependencies...
python -c "import flask, flask_sqlalchemy, flask_login, werkzeug, humanize, flask_wtf" >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    ECHO [INFO] Dependencies not found or incomplete. Installing from requirements.txt...
    pip install -r requirements.txt
    IF %ERRORLEVEL% NEQ 0 (
        ECHO [ERROR] Failed to install dependencies. Please check your internet connection.
        PAUSE
        EXIT /B 1
    )
    ECHO [SUCCESS] Dependencies installed successfully!
) ELSE (
    ECHO [SUCCESS] All dependencies are already installed.
)

:: Check if app.py exists
IF NOT EXIST app.py (
    ECHO [ERROR] The file app.py does not exist in this directory.
    PAUSE
    EXIT /B 1
)

:: Create necessary directories if they don't exist
IF NOT EXIST user_uploads (
    ECHO [INFO] Creating user_uploads directory...
    mkdir user_uploads
)

:: Launch Flask server
ECHO.
ECHO [INFO] Starting Sephosting server...
ECHO [INFO] Access the application in your browser: http://127.0.0.1:83
ECHO [INFO] Press CTRL+C to stop the server
ECHO.
ECHO [INFO] Default administrator credentials:
ECHO       Username: Admin
ECHO       Password: Admin
ECHO       (You will need to change these credentials on first login)
ECHO.
ECHO ===================================
ECHO.

:: Run Flask application
python app.py

PAUSE 