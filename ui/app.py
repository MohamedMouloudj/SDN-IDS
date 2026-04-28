"""app.py - Flask web interface for SDN IDS dashboard.

Two pages:
    /           -> dashboard  (login required, all users)
    /users      -> user management (admin only)
    /login      -> login page
    /logout     -> logout
    /stream     -> SSE endpoint for real-time stats

Run from the ryu-controller directory so models.py resolves correctly:
    cd ryu-controller
    python ../ui/app.py
"""

import os
import sys
import json
import time
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, redirect, url_for,
    request, session, Response, jsonify, flash,
)

# resolve models.py from parent directory (ryu-controller/)
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from models import Session as DBSession, History, User, Packets_dropped

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET', 'sdn-ids-secret-2026')

# ── Jinja2 custom filters ────────────────────────────────────

@app.template_filter('format_ts')
def format_ts(ts):
    """Format a unix timestamp to HH:MM:SS."""
    try:
        return datetime.fromtimestamp(float(ts)).strftime('%H:%M:%S')
    except Exception:
        return '-'

@app.template_filter('count_values')
def count_values(json_str):
    """Sum all values in a JSON dict string."""
    try:
        d = json.loads(json_str) if isinstance(json_str, str) else json_str
        return f"{sum(d.values()):,}"
    except Exception:
        return '0'

ADMIN_EMAIL = 'admin@gmail.com'
ADMIN_PASSWORD = 'admin'

# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        if not session.get('is_admin'):
            flash('Admin access required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email    = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        # Check hardcoded admin first
        if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:
            session['user']     = 'admin'
            session['email']    = email
            session['is_admin'] = True
            return redirect(url_for('dashboard'))

        # Check DB users
        db = DBSession()
        try:
            user = db.query(User).filter_by(Email=email, Password=password).first()
            if user:
                session['user']     = user.Name
                session['email']    = user.Email
                session['is_admin'] = False
                return redirect(url_for('dashboard'))
        finally:
            db.close()

        flash('Invalid credentials.', 'error')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.route('/')
@login_required
def dashboard():
    db = DBSession()
    try:
        # last 10 attack events
        recent = (db.query(History)
                  .order_by(History.Timestamp.desc())
                  .limit(10)
                  .all())

        # packets dropped counter
        dropped = db.query(Packets_dropped).first()
        dropped_count = dropped.Count if dropped else 0
        dropped_size  = dropped.Size  if dropped else 0.0

        # attack type distribution (all time)
        all_attacks = db.query(History).all()
        type_counts = {}
        for row in all_attacks:
            t = row.Attack_type or 'Unknown'
            type_counts[t] = type_counts.get(t, 0) + 1

        # action distribution
        action_counts = {}
        for row in all_attacks:
            a = row.Action or 'unknown'
            action_counts[a] = action_counts.get(a, 0) + 1

    finally:
        db.close()

    return render_template(
        'dashboard.html',
        recent=recent,
        dropped_count=dropped_count,
        dropped_size=dropped_size,
        type_counts=json.dumps(type_counts),
        action_counts=json.dumps(action_counts),
        user=session['user'],
        is_admin=session.get('is_admin', False),
    )


# ---------------------------------------------------------------------------
# SSE stream
# ---------------------------------------------------------------------------

def _get_stats():
    """Fetch current stats snapshot from DB."""
    db = DBSession()
    try:
        dropped = db.query(Packets_dropped).first()

        recent = (db.query(History)
                  .order_by(History.Timestamp.desc())
                  .limit(10)
                  .all())

        type_counts = {}
        action_counts = {}
        for row in db.query(History).all():
            t = row.Attack_type or 'Unknown'
            type_counts[t] = type_counts.get(t, 0) + 1
            a = row.Action or 'unknown'
            action_counts[a] = action_counts.get(a, 0) + 1

        # active bans (Ban_expiry > now)
        now = time.time()
        active_bans = (db.query(History)
                       .filter(History.Ban_expiry > now)
                       .filter(History.Action == 'ip_banned')
                       .all())

        return {
            'dropped_count':  dropped.Count if dropped else 0,
            'dropped_size':   dropped.Size  if dropped else 0.0,
            'type_counts':    type_counts,
            'action_counts':  action_counts,
            'active_bans':    len(active_bans),
            'recent': [
                {
                    'timestamp':   datetime.fromtimestamp(r.Timestamp).strftime('%H:%M:%S') if r.Timestamp else '-',
                    'attack_type': r.Attack_type or '-',
                    'attacker':    r.Attacker    or '-',
                    'victim':      r.Victim      or '-',
                    'port':        r.Port        or '-',
                    'action':      r.Action      or '-',
                    'protocole':   r.Protocole   or '-',
                    'expiry':      datetime.fromtimestamp(r.Ban_expiry).strftime('%H:%M:%S')
                                   if r.Ban_expiry and r.Ban_expiry > 0 else 'Permanent',
                }
                for r in recent
            ],
        }
    finally:
        db.close()


@app.route('/stream')
@login_required
def stream():
    """SSE endpoint. Pushes a stats update every 5 seconds."""
    def event_generator():
        while True:
            try:
                data = _get_stats()
                yield f"data: {json.dumps(data)}\n\n"
            except Exception as exc:
                yield f"data: {json.dumps({'error': str(exc)})}\n\n"
            time.sleep(5)

    return Response(
        event_generator(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
        },
    )


# ---------------------------------------------------------------------------
# User management (admin only)
# ---------------------------------------------------------------------------

@app.route('/users')
@admin_required
def users():
    db = DBSession()
    try:
        all_users = db.query(User).all()
    finally:
        db.close()
    return render_template(
        'users.html',
        users=all_users,
        user=session['user'],
        is_admin=True,
    )


@app.route('/users/create', methods=['POST'])
@admin_required
def create_user():
    name     = request.form.get('name', '').strip()
    email    = request.form.get('email', '').strip()
    password = request.form.get('password', '').strip()

    if not all([name, email, password]):
        flash('All fields are required.', 'error')
        return redirect(url_for('users'))

    db = DBSession()
    try:
        exists = db.query(User).filter_by(Email=email).first()
        if exists:
            flash('Email already exists.', 'error')
            return redirect(url_for('users'))

        db.add(User(Name=name, Email=email, Password=password))
        db.commit()
        flash(f'User {name} created.', 'success')
    except Exception as exc:
        db.rollback()
        flash(f'Error: {exc}', 'error')
    finally:
        db.close()

    return redirect(url_for('users'))


@app.route('/users/delete/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    db = DBSession()
    try:
        u = db.query(User).filter_by(id=user_id).first()
        if u:
            db.delete(u)
            db.commit()
            flash(f'User {u.Name} deleted.', 'success')
    except Exception as exc:
        db.rollback()
        flash(f'Error: {exc}', 'error')
    finally:
        db.close()
    return redirect(url_for('users'))


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)