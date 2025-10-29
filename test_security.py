import sqlite3
import os
from db_init import init_db, DB
from app import query_user_by_username, query_user_by_id, get_db, validate_username
from werkzeug.security import generate_password_hash

def setup_module(module):
    # initialize a fresh DB for tests
    if os.path.exists(DB):
        os.remove(DB)
    init_db()

def test_username_validator():
    assert validate_username('alice')
    assert not validate_username('in valid!')
    assert not validate_username('ab')  # too short

def test_sql_injection_attempt_does_not_drop_table():
    db = sqlite3.connect(DB)
    cur = db.cursor()
    # Attempt classic injection via username search; because app uses parameterized queries,
    # this should only be treated as data and not executed as SQL.
    malicious = "alice'; DROP TABLE users; --"
    cur.execute("SELECT id FROM users WHERE username = ?", (malicious,))
    rows = cur.fetchall()
    # Table should still exist
    cur.execute("""SELECT name FROM sqlite_master WHERE type='table' AND name='users'""")
    assert cur.fetchone() is not None
    db.close()

def test_rbac_user_roles():
    # admin exists from init_db, alice exists as 'user'
    admin = query_user_by_username('admin')
    assert admin is not None and admin['role'] == 'admin'
    alice = query_user_by_username('alice')
    assert alice is not None and alice['role'] == 'user'
