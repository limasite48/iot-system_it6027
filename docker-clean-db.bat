@echo off
REM ==============================================================================
REM IoT Insecure Device Detection & Governance Platform - Database Cleaner (Windows)
REM Course: IT6027 - Cyber Security Policy and Governance
REM ==============================================================================

echo ====================================================================
echo  Cleaning Stale / Ghost Devices from SQLite Database
echo ====================================================================

python net-sec\clean_db.py

pause
