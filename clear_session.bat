@echo off
TITLE Sephosting Session Reset
COLOR 0E

ECHO ===================================
ECHO      SEPHOSTING SESSION RESET
ECHO ===================================
ECHO.
ECHO Cette opération va effacer les sessions et redémarrer l'application.
ECHO.

:: Arrêter le serveur Flask s'il est en cours d'exécution
TASKKILL /F /IM python.exe /T >nul 2>&1

:: Supprimer les fichiers de session
ECHO [INFO] Suppression des fichiers de session...
IF EXIST instance\*.session (
    DEL /F instance\*.session >nul 2>&1
    ECHO [SUCCESS] Fichiers de session supprimés.
) ELSE (
    ECHO [INFO] Aucun fichier de session trouvé.
)

:: Supprimer les cookies du navigateur
ECHO [INFO] Pour compléter le processus:
ECHO 1. Fermez votre navigateur
ECHO 2. Effacez les cookies pour le site (127.0.0.1)
ECHO 3. Redémarrez l'application avec start_server.bat
ECHO.

ECHO [INFO] Prêt à redémarrer l'application.
ECHO.
ECHO ===================================

SET /P RESTART=Voulez-vous redémarrer l'application maintenant? (O/N): 

IF /I "%RESTART%" EQU "O" (
    ECHO.
    ECHO [INFO] Redémarrage de l'application...
    START start_server.bat
)

PAUSE 