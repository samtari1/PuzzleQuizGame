import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, abort, flash, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_urlsafe(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax',
                  SESSION_COOKIE_SECURE=os.environ.get('APP_ENV') == 'production')
DB_PATH = os.environ.get('DATABASE_PATH', os.path.join(os.path.dirname(__file__), 'game.db'))
INSTRUCTOR_PASSWORD = os.environ.get('INSTRUCTOR_PASSWORD', '')
GUESS_LIMIT = 8
GUESS_WINDOW = 60

# Serialize check-and-finish operations across threads in this process. SQLite transactions
# additionally protect the one-success-per-team constraint across workers.
write_lock = threading.RLock()


def connect():
    db = sqlite3.connect(DB_PATH, timeout=15, isolation_level=None)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    db.execute('PRAGMA busy_timeout=15000')
    return db


def init_db():
    with connect() as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS games (
          id INTEGER PRIMARY KEY AUTOINCREMENT, status TEXT NOT NULL DEFAULT 'ready',
          started_at REAL, paused_at REAL, elapsed_before_pause REAL NOT NULL DEFAULT 0,
          recovery_hash TEXT, created_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS teams (
          id INTEGER PRIMARY KEY AUTOINCREMENT, game_id INTEGER NOT NULL REFERENCES games(id) ON DELETE CASCADE,
          name TEXT NOT NULL, code_hash TEXT NOT NULL, finished_at REAL, elapsed REAL,
          response TEXT NOT NULL DEFAULT '', UNIQUE(game_id, name)
        );
        CREATE TABLE IF NOT EXISTS attempts (
          id INTEGER PRIMARY KEY AUTOINCREMENT, team_id INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
          attempted_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS attempt_window ON attempts(team_id, attempted_at);
        CREATE INDEX IF NOT EXISTS finished_order ON teams(game_id, finished_at);
        ''')
        columns = {row['name'] for row in db.execute('PRAGMA table_info(games)')}
        if 'recovery_hash' not in columns:
            db.execute('ALTER TABLE games ADD COLUMN recovery_hash TEXT')


init_db()


def now():
    return time.time()


def current_game(db):
    return db.execute('SELECT * FROM games ORDER BY id DESC LIMIT 1').fetchone()


def elapsed(game, at=None):
    at = at or now()
    if game['status'] == 'running' and game['started_at'] is not None:
        return max(0, game['elapsed_before_pause'] + at - game['started_at'])
    return max(0, game['elapsed_before_pause'])


def duration_label(seconds):
    seconds = max(0, int(seconds))
    return f'{seconds // 60:02d}:{seconds % 60:02d}'


def team_code_hash(code):
    return hashlib.sha256(code.encode('utf-8')).hexdigest()


def instructor_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get('instructor'):
            return redirect(url_for('instructor_login', next=request.path))
        return fn(*args, **kwargs)
    return wrapped


def game_data(db, game):
    teams = db.execute('SELECT id,name,finished_at,elapsed,response FROM teams WHERE game_id=? ORDER BY finished_at IS NULL, finished_at, id', (game['id'],)).fetchall()
    return teams


@app.after_request
def security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Referrer-Policy'] = 'same-origin'
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'"
    return response


@app.route('/')
def home():
    return redirect(url_for('team_entry'))


@app.route('/team', methods=['GET', 'POST'])
def team_entry():
    message = None
    success = False
    completed_time = None
    response_saved = False
    with connect() as db:
        game = current_game(db)
        if game is None or game['status'] == 'ready':
            return render_template('team.html', game_ready=False)
        team = None
        if request.method == 'POST':
            action = request.form.get('action', 'submit')
            access_code = request.form.get('access_code', '').strip().upper()
            entered_name = request.form.get('team_name', '').strip()[:40]
            if action == 'response':
                team = db.execute('SELECT * FROM teams WHERE id=? AND game_id=?', (session.get('team_id'), game['id'])).fetchone()
                if not team or not team['finished_at']:
                    message = 'Unlock the challenge before sending your response.'
                else:
                    text = request.form.get('response', '').strip()[:2000]
                    db.execute('UPDATE teams SET response=? WHERE id=? AND game_id=?', (text, team['id'], game['id']))
                    response_saved = True
                    success = True
                    completed_time = duration_label(team['elapsed'])
                    message = 'Your response has been saved.'
            elif len(access_code) < 6 or len(access_code) > 12 or not access_code.isalnum():
                message = 'Enter the team access code provided by your instructor.'
            else:
                team = db.execute('SELECT * FROM teams WHERE game_id=? AND code_hash=?', (game['id'], team_code_hash(access_code))).fetchone()
                if not team or not hmac.compare_digest(team['name'].casefold(), entered_name.casefold()):
                    # Keep team identity and access-code checks indistinguishable.
                    message = 'Team details not recognized.'
                elif game['status'] != 'running' and not team['finished_at']:
                    message = 'The instructor has not started the timer yet.'
                elif team['finished_at']:
                    success = True
                    completed_time = duration_label(team['elapsed'])
                    session['team_id'] = team['id']
                else:
                    with write_lock:
                        db.execute('BEGIN IMMEDIATE')
                        current = db.execute('SELECT * FROM teams WHERE id=? AND game_id=?', (team['id'], game['id'])).fetchone()
                        if current['finished_at']:
                            success = True
                            completed_time = duration_label(current['elapsed'])
                            session['team_id'] = team['id']
                        else:
                            cutoff = now() - GUESS_WINDOW
                            db.execute('DELETE FROM attempts WHERE team_id=? AND attempted_at<?', (team['id'], cutoff))
                            count = db.execute('SELECT COUNT(*) FROM attempts WHERE team_id=?', (team['id'],)).fetchone()[0]
                            if count >= GUESS_LIMIT:
                                message = 'Too many attempts. Please wait a minute before trying again.'
                            else:
                                db.execute('INSERT INTO attempts(team_id,attempted_at) VALUES(?,?)', (team['id'], now()))
                                submitted = ''.join(ch for ch in request.form.get('recovery_code', '') if ch.isdigit())
                                if len(submitted) == 5 and submitted.isdigit() and game['recovery_hash'] and check_password_hash(game['recovery_hash'], submitted):
                                    stamp = now()
                                    fresh_game = db.execute('SELECT * FROM games WHERE id=?', (game['id'],)).fetchone()
                                    team_elapsed = elapsed(fresh_game, stamp)
                                    db.execute('UPDATE teams SET finished_at=?, elapsed=? WHERE id=? AND finished_at IS NULL', (stamp, team_elapsed, team['id']))
                                    completed_time = duration_label(team_elapsed)
                                    success = True
                                    session['team_id'] = team['id']
                                else:
                                    message = 'Incorrect—check your answers and try again.'
                        db.execute('COMMIT')
            # On successful submission, fetch latest row so incident response is displayed.
            if success and team:
                team = db.execute('SELECT * FROM teams WHERE id=?', (team['id'],)).fetchone()
        elif session.get('team_id'):
            team = db.execute('SELECT * FROM teams WHERE id=? AND game_id=?', (session['team_id'], game['id'])).fetchone()
            if team and team['finished_at']:
                success = True
                completed_time = duration_label(team['elapsed'])
        return render_template('team.html', game_ready=True, game_status=game['status'], message=message,
                               success=success, completed_time=completed_time, team=team,
                               response_saved=response_saved)


@app.route('/team/logout', methods=['POST'])
def team_logout():
    session.pop('team_id', None)
    return redirect(url_for('team_entry'))


@app.route('/instructor/login', methods=['GET', 'POST'])
def instructor_login():
    if not INSTRUCTOR_PASSWORD:
        return render_template('login.html', error='Set INSTRUCTOR_PASSWORD in your environment before using instructor controls.'), 503
    error = None
    if request.method == 'POST':
        if hmac.compare_digest(request.form.get('password', ''), INSTRUCTOR_PASSWORD):
            session['instructor'] = True
            return redirect(request.args.get('next') or url_for('instructor'))
        error = 'Password did not match.'
    return render_template('login.html', error=error)


@app.route('/instructor/logout', methods=['POST'])
def instructor_logout():
    session.pop('instructor', None)
    return redirect(url_for('instructor_login'))


@app.route('/instructor', methods=['GET', 'POST'])
@instructor_required
def instructor():
    issued_codes = session.pop('issued_codes', None)
    notice = None
    with connect() as db:
        game = current_game(db)
        if request.method == 'POST':
            action = request.form.get('action')
            if action == 'new_game':
                # Starting a new session deletes all previous class data and creates a fresh game.
                confirmed = request.form.get('confirm_reset') == 'yes'
                if not confirmed:
                    notice = 'Confirm the reset checkbox to create a fresh session and delete the previous class results.'
                else:
                    names = [line.strip()[:40] for line in request.form.get('team_names', '').splitlines() if line.strip()]
                    recovery_code = request.form.get('recovery_code', '').strip()
                    if not names:
                        notice = 'Enter at least one team name, with one team per line.'
                    elif len(names) > 100 or len(set(name.casefold() for name in names)) != len(names):
                        notice = 'Use up to 100 unique team names.'
                    elif len(recovery_code) != 5 or not recovery_code.isdigit():
                        notice = 'Enter a five-digit recovery code for this session.'
                    else:
                        with write_lock:
                            db.execute('BEGIN IMMEDIATE')
                            db.execute('DELETE FROM games')
                            cur = db.execute("INSERT INTO games(status,created_at,recovery_hash) VALUES('ready',?,?)", (now(), generate_password_hash(recovery_code, method='pbkdf2:sha256')))
                            gid = cur.lastrowid
                            codes = []
                            for name in names:
                                code = secrets.token_urlsafe(6).replace('-', '').replace('_', '').upper()[:8]
                                while code in codes:
                                    code = secrets.token_urlsafe(6).replace('-', '').replace('_', '').upper()[:8]
                                codes.append(code)
                                db.execute('INSERT INTO teams(game_id,name,code_hash) VALUES(?,?,?)', (gid, name, team_code_hash(code)))
                            db.execute('COMMIT')
                        session['issued_codes'] = list(zip(names, codes))
                        return redirect(url_for('instructor'))
            elif game:
                if action == 'start' and game['status'] in ('ready', 'paused'):
                    if game['status'] == 'ready':
                        db.execute("UPDATE games SET status='running',started_at=? WHERE id=?", (now(), game['id']))
                    else:
                        db.execute("UPDATE games SET status='running',started_at=? WHERE id=?", (now(), game['id']))
                    notice = 'Timer started.' if game['status'] == 'ready' else 'Timer resumed.'
                elif action == 'pause' and game['status'] == 'running':
                    db.execute("UPDATE games SET elapsed_before_pause=?,paused_at=?,started_at=NULL,status='paused' WHERE id=?", (elapsed(game), now(), game['id']))
                    notice = 'Timer paused.'
                elif action == 'reset_timer':
                    db.execute("UPDATE games SET status='paused',started_at=NULL,paused_at=?,elapsed_before_pause=0 WHERE id=?", (now(), game['id']))
                    notice = 'Timer reset to 00:00 and paused. Team results are still recorded; resume when ready.'
                elif action == 'save_response':
                    team_id = request.form.get('team_id', type=int)
                    text = request.form.get('response', '').strip()[:2000]
                    db.execute('UPDATE teams SET response=? WHERE id=? AND game_id=?', (text, team_id, game['id']))
                    notice = 'Response saved.'
            return redirect(url_for('instructor', notice=notice))
        if request.args.get('notice'):
            notice = request.args.get('notice')
        game = current_game(db)
        teams = game_data(db, game) if game else []
        return render_template('instructor.html', game=game, teams=teams, timer=duration_label(elapsed(game)) if game else '00:00',
                               notice=notice, issued_codes=issued_codes)


@app.route('/scoreboard')
def scoreboard():
    return render_template('scoreboard.html')


@app.route('/api/scoreboard')
def scoreboard_api():
    with connect() as db:
        game = current_game(db)
        if not game:
            return jsonify({'active': False, 'status': 'empty', 'timer': '00:00', 'teams': []})
        teams = db.execute('SELECT name,elapsed FROM teams WHERE game_id=? AND finished_at IS NOT NULL ORDER BY finished_at,id', (game['id'],)).fetchall()
        return jsonify({'active': True, 'status': game['status'], 'timer': duration_label(elapsed(game)),
                        'teams': [{'name': t['name'], 'time': duration_label(t['elapsed'])} for t in teams]})


@app.route('/healthz')
def healthz():
    return jsonify({'ok': True})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', '5000')))
