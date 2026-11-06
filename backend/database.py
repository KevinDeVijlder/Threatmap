"""
SQLite Database Layer
=====================
Handles schema initialization, automatic migrations, password hashing,
session token lookup, and user profile persistence (avatars, custom feeds,
and monitored map locations).
"""

import hashlib
import json
import secrets
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple

from config import DB_PATH, logger


def get_db_connection() -> sqlite3.Connection:
    """Returns a SQLite connection with row factory configured."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Creates the SQLite database tables for users and sessions if they do not exist, and runs migrations."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            avatar TEXT DEFAULT '',
            custom_sources TEXT DEFAULT '[]',
            custom_locations TEXT DEFAULT '[]',
            created_at REAL NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at REAL NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    # Safe schema migration for existing databases created before custom_locations was added
    cursor.execute("PRAGMA table_info(users)")
    existing_cols = {row[1] for row in cursor.fetchall()}
    if "custom_locations" not in existing_cols:
        cursor.execute("ALTER TABLE users ADD COLUMN custom_locations TEXT DEFAULT '[]'")
        logger.info("Migrated SQLite 'users' table to include 'custom_locations' column.")

    conn.commit()
    conn.close()
    logger.info(f"SQLite database initialized at {DB_PATH}")


def hash_password(password: str, salt: str) -> str:
    """Hashes a password using PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000
    ).hex()


def get_user_by_raw_token(token: Optional[str]) -> Optional[Dict]:
    """Resolves a raw session token into a user dictionary."""
    if not token:
        return None
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT u.id, u.username, u.avatar, u.custom_sources, u.custom_locations
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.token = ?
    """, (token.strip(),))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "id": row["id"],
        "username": row["username"],
        "avatar": row["avatar"] or "",
        "custom_sources": json.loads(row["custom_sources"] or "[]"),
        "custom_locations": json.loads(row["custom_locations"] or "[]"),
    }


def get_user_by_token(authorization: Optional[str]) -> Optional[Dict]:
    """Resolves a Bearer token from the HTTP Authorization header."""
    if not authorization or not authorization.startswith("Bearer "):
        return None
    token = authorization.split(" ", 1)[1].strip()
    return get_user_by_raw_token(token)


def get_user_custom_sources(user_id: int) -> List[Dict]:
    """Fetches the latest custom_sources list for a specific user_id from SQLite."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT custom_sources FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return []
    return json.loads(row["custom_sources"] or "[]")


def get_user_custom_locations(user_id: int) -> List[Dict]:
    """Fetches the latest custom_locations list for a specific user_id from SQLite."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT custom_locations FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return []
    return json.loads(row["custom_locations"] or "[]")


def create_user_and_session(username: str, password: str, avatar: str = "") -> Tuple[str, Dict]:
    """Creates a new user account and an initial session token. Raises sqlite3.IntegrityError if duplicate."""
    salt = secrets.token_hex(16)
    pwd_hash = hash_password(password, salt)
    now = time.time()

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, salt, avatar, custom_sources, custom_locations, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (username, pwd_hash, salt, avatar or "", "[]", "[]", now),
        )
        user_id = cursor.lastrowid
        token = secrets.token_urlsafe(32)
        cursor.execute(
            "INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)",
            (token, user_id, now),
        )
        conn.commit()
    finally:
        conn.close()

    user_dict = {
        "id": user_id,
        "username": username,
        "avatar": avatar or "",
        "custom_sources": [],
        "custom_locations": [],
    }
    return token, user_dict


def authenticate_user(username: str, password: str) -> Optional[Tuple[str, Dict]]:
    """Verifies user credentials and creates a new session token if valid."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()

    if not row or hash_password(password, row["salt"]) != row["password_hash"]:
        conn.close()
        return None

    token = secrets.token_urlsafe(32)
    cursor.execute(
        "INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)",
        (token, row["id"], time.time()),
    )
    conn.commit()
    conn.close()

    user_dict = {
        "id": row["id"],
        "username": row["username"],
        "avatar": row["avatar"] or "",
        "custom_sources": json.loads(row["custom_sources"] or "[]"),
        "custom_locations": json.loads(row["custom_locations"] or "[]"),
    }
    return token, user_dict


def update_user_avatar(user_id: int, avatar: str) -> None:
    """Updates the Base64 avatar string for a user."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET avatar = ? WHERE id = ?", (avatar, user_id))
    conn.commit()
    conn.close()


def update_user_sources(user_id: int, custom_sources: List[Dict[str, str]]) -> None:
    """Updates the JSON-serialized custom OSINT sources for a user."""
    sources_json = json.dumps(custom_sources)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET custom_sources = ? WHERE id = ?", (sources_json, user_id))
    conn.commit()
    conn.close()


def update_user_locations(user_id: int, custom_locations: List[Dict[str, Any]]) -> None:
    """Updates the JSON-serialized custom monitored locations for a user."""
    locations_json = json.dumps(custom_locations)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET custom_locations = ? WHERE id = ?", (locations_json, user_id))
    conn.commit()
    conn.close()


def delete_session(token: str) -> None:
    """Deletes a session token from the database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM sessions WHERE token = ?", (token,))
    conn.commit()
    conn.close()
