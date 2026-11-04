#!/usr/bin/env python3
"""
Initialize or reset the SQLite database (pcd.db) with default users and roles.
"""
import hashlib
import os
import sqlite3
import sys
import uuid

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)

def init_db(db_path="pcd.db"):
    print(f"Initializing database at: {db_path}")
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS USERS (
        UUID TEXT PRIMARY KEY,
        USERNAME TEXT NOT NULL UNIQUE,
        PASSWORD TEXT NOT NULL,
        ROLE INT NOT NULL DEFAULT 0
    )
    """)

    default_users = [
        ("alice", "pass123", 0),  # Regular user
        ("bob", "secret", 0),    # Regular user
        ("admin", "admin123", 1),# Administrator
        ("root", "adminpw", 1),  # Administrator
    ]

    for username, password, role in default_users:
        # Check if user already exists
        cur.execute("SELECT UUID FROM USERS WHERE USERNAME = ?", (username,))
        row = cur.fetchone()
        hashed_pw = hashlib.sha512(password.encode("utf-8")).hexdigest()

        if row:
            # Update password and role
            cur.execute("UPDATE USERS SET PASSWORD = ?, ROLE = ? WHERE USERNAME = ?", (hashed_pw, role, username))
            print(f"  [Updated]  User: {username:8} | Role: {'Admin (1)' if role == 1 else 'User (0)'}")
        else:
            user_id = str(uuid.uuid4())
            cur.execute("INSERT INTO USERS (UUID, USERNAME, PASSWORD, ROLE) VALUES (?, ?, ?, ?)",
                        (user_id, username, hashed_pw, role))
            print(f"  [Created]  User: {username:8} | Password: {password:8} | Role: {'Admin (1)' if role == 1 else 'User (0)'}")

    conn.commit()
    conn.close()
    print("Database initialized successfully.")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "pcd.db"
    init_db(target)
