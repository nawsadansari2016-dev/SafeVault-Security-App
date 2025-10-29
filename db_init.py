import sqlite3
from werkzeug.security import generate_password_hash

DB = 'safevault.sqlite3'

def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL
    )''')
    # Insert two users: admin and user
    c.execute('INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?,?,?)',
              ('admin', generate_password_hash('AdminPass123!'), 'admin'))
    c.execute('INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?,?,?)',
              ('alice', generate_password_hash('AlicePass123!'), 'user'))
    conn.commit()
    conn.close()
    print("Initialized database:", DB)

if __name__ == "__main__":
    init_db()
