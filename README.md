# SafeVault Secure Application (Minimal)

This is a minimal secure example of the **SafeVault** application built with Flask.
It showcases:
- Parameterized queries to prevent SQL Injection
- Input validation functions for critical fields
- Role-Based Access Control (RBAC) for routes
- Password hashing using Werkzeug
- Basic XSS mitigation (Jinja2 auto-escaping and Content-Security-Policy header)
- Small test suite to validate security protections

## How to run (locally)
1. Create a virtual environment and install dependencies from `requirements.txt`.
2. Initialize the database: `python db_init.py`
3. Run the app: `python app.py`
4. Run tests: `pytest -q`

## Files
- `app.py` — Main Flask application with secure patterns.
- `db_init.py` — Creates a SQLite database with sample users and roles.
- `tests/test_security.py` — Basic tests checking SQL injection resistance and RBAC.
- `templates/` — Simple HTML templates.

## Copilot usage
Copilot was used to suggest patterns for parameterized queries, role-check decorators, and sample test cases. All final code was reviewed and adjusted to ensure clarity and correct behavior.
