"""SQLite storage: users, login sessions, and one persisted workspace per user."""
import hashlib
import hmac
import os
import pickle
import secrets
import sqlite3
import threading
import time

from .config import ROOT

DB_PATH = os.path.join(ROOT, "data", "driftguard.db")
_lock = threading.Lock()


def _conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    c = sqlite3.connect(DB_PATH, check_same_thread=False)
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT UNIQUE, name TEXT, org TEXT, salt TEXT, pw TEXT, created REAL)")
    c.execute("CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id INTEGER, created REAL)")
    c.execute("CREATE TABLE IF NOT EXISTS workspaces (user_id INTEGER PRIMARY KEY, blob BLOB)")
    return c


CONN = _conn()


def _hash(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 200_000).hex()


def create_user(email, name, org, password):
    salt = secrets.token_hex(16)
    with _lock:
        cur = CONN.execute("INSERT INTO users (email, name, org, salt, pw, created) VALUES (?,?,?,?,?,?)",
                           (email.lower().strip(), name.strip(), org.strip(), salt, _hash(password, salt), time.time()))
        CONN.commit()
        return cur.lastrowid


def check_login(email, password):
    row = CONN.execute("SELECT id, salt, pw FROM users WHERE email=?", (email.lower().strip(),)).fetchone()
    if row and hmac.compare_digest(_hash(password, row[1]), row[2]):
        return row[0]
    return None


def user(uid):
    row = CONN.execute("SELECT id, email, name, org FROM users WHERE id=?", (uid,)).fetchone()
    return dict(zip(("id", "email", "name", "org"), row)) if row else None


def new_session(uid):
    tok = secrets.token_urlsafe(32)
    with _lock:
        CONN.execute("INSERT INTO sessions VALUES (?,?,?)", (tok, uid, time.time()))
        CONN.commit()
    return tok


def session_user(tok):
    row = CONN.execute("SELECT user_id FROM sessions WHERE token=?", (tok or "",)).fetchone()
    return row[0] if row else None


def end_session(tok):
    with _lock:
        CONN.execute("DELETE FROM sessions WHERE token=?", (tok or "",))
        CONN.commit()


def save_workspace(uid, state):
    blob = pickle.dumps(state)
    with _lock:
        CONN.execute("INSERT OR REPLACE INTO workspaces VALUES (?,?)", (uid, blob))
        CONN.commit()


def load_workspaces():
    return {uid: pickle.loads(blob) for uid, blob in CONN.execute("SELECT user_id, blob FROM workspaces").fetchall()}
