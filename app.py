from flask import Flask, request, render_template, redirect, url_for, flash, session, g, abort, make_response
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, re, functools
DB = 'safevault.sqlite3'

app = Flask(__name__)
app.secret_key = 'replace-this-secret-with-env-var-in-prod'

# Simple input validators
username_re = re.compile(r'^[A-Za-z0-9_]{3,30}$')
def validate_username(u):
    return bool(username_re.match(u))

def validate_password(p):
    return isinstance(p, str) and len(p) >= 8

# Database helper using parameterized queries
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def query_user_by_username(username):
    db = get_db()
    # Parameterized query prevents SQL injection
    cur = db.execute('SELECT id, username, password_hash, role FROM users WHERE username = ?', (username,))
    return cur.fetchone()

# Simple role check decorator
def require_role(role):
    def decorator(f):
        @functools.wraps(f)
        def wrapped(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login', next=request.endpoint))
            user = query_user_by_id(session['user_id'])
            if not user or user['role'] != role:
                abort(403)
            return f(*args, **kwargs)
        return wrapped
    return decorator

def query_user_by_id(uid):
    db = get_db()
    cur = db.execute('SELECT id, username, password_hash, role FROM users WHERE id = ?', (uid,))
    return cur.fetchone()

@app.after_request
def set_security_headers(response):
    # Basic CSP to mitigate XSS risks and clickjacking
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; object-src 'none'"
    response.headers['X-Frame-Options'] = 'DENY'
    return response

@app.route('/')
def index():
    user = None
    if 'user_id' in session:
        user = query_user_by_id(session['user_id'])
    return render_template('index.html', user=user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        # Validate inputs
        if not validate_username(username):
            flash('Invalid username format.')
            return redirect(url_for('login'))
        user = query_user_by_username(username)
        if user and check_password_hash(user['password_hash'], password):
            session.clear()
            session['user_id'] = user['id']
            flash('Logged in successfully.')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials.')
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = query_user_by_id(session['user_id'])
    # Safe rendering: Jinja2 autoescaping will escape any user content inserted
    return render_template('dashboard.html', user=user)

@app.route('/admin-only')
@require_role('admin')
def admin_only():
    return 'Welcome, admin!'

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.')
    return redirect(url_for('index'))

# Example of a safe search endpoint — uses parameterized queries and input validation
@app.route('/search')
def search():
    q = request.args.get('q', '').strip()
    # Very basic validation: limit length to avoid DoS
    if len(q) > 200:
        abort(400)
    db = get_db()
    # Use LIKE safely with parameterized query and explicit wildcard concatenation
    cur = db.execute('SELECT id, username, role FROM users WHERE username LIKE ? LIMIT 25', (f'%{q}%',))
    results = cur.fetchall()
    return render_template('index.html', results=results, user=query_user_by_id(session.get('user_id')))

if __name__ == '__main__':
    # Ensure DB exists (simple auto-init if not present)
    import os
    if not os.path.exists(DB):
        from db_init import init_db
        init_db()
    app.run(debug=True, port=5000)
