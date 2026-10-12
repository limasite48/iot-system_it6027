"""
Database & Persistence Package (net-sec)
Provides relational SQLite storage for scans, devices, findings, and auditor triage.
"""
from app.db.database import DatabaseManager, GLOBAL_DB_MANAGER

__all__ = ["DatabaseManager", "GLOBAL_DB_MANAGER"]
