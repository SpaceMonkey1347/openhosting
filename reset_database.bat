@echo off
TITLE Sephosting Database Reset
COLOR 0C

ECHO ===================================
ECHO      SEPHOSTING DATABASE RESET
ECHO ===================================
ECHO.
ECHO ATTENTION: Cette opération va supprimer toutes les données!
ECHO Tous les utilisateurs et fichiers seront perdus.
ECHO.
SET /P CONFIRM=Êtes-vous sûr de vouloir continuer? (O/N): 

IF /I "%CONFIRM%" NEQ "O" (
    ECHO Opération annulée.
    PAUSE
    EXIT /B 0
)

ECHO.
ECHO [INFO] Suppression de la base de données...

IF EXIST instance\site.db (
    DEL /F instance\site.db
    ECHO [SUCCESS] Base de données supprimée avec succès.
) ELSE (
    ECHO [INFO] Aucune base de données trouvée.
)

ECHO.
ECHO [INFO] Redémarrez l'application pour créer une nouvelle base de données.
ECHO [INFO] L'utilisateur administrateur par défaut sera recréé:
ECHO       Utilisateur: Ciel
ECHO       Mot de passe: Buster2009@
ECHO.
ECHO ===================================

PAUSE 