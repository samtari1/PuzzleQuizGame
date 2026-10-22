import hashlib
import hmac
import base64
import os
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, abort, flash, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from cryptography.fernet import Fernet, InvalidToken

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_urlsafe(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax',
                  SESSION_COOKIE_SECURE=os.environ.get('APP_ENV') == 'production')
DB_PATH = os.environ.get('DATABASE_PATH', os.path.join(os.path.dirname(__file__), 'game.db'))
INSTRUCTOR_PASSWORD = os.environ.get('INSTRUCTOR_PASSWORD', '')
GUESS_LIMIT = 8
GUESS_WINDOW = 60
DEFAULT_INCIDENT_PROMPT = 'Who are the team members on your team?'
PREVIOUS_DEFAULT_INCIDENT_PROMPT = ('A student receives a message that looks like an official Canvas notice and asks them to verify a password through a link. '
                                    'What should the student do first, how should they verify the message, and whom should they notify?')

# Serialize check-and-finish operations across threads in this process. SQLite transactions
# additionally protect the one-success-per-team constraint across workers.
write_lock = threading.RLock()


def access_code_cipher():
    key = hashlib.sha256(('ict-escape-team-codes:' + app.secret_key).encode('utf-8')).digest()
    return Fernet(base64.urlsafe_b64encode(key))


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
        CREATE TABLE IF NOT EXISTS instructor_auth (
          id INTEGER PRIMARY KEY CHECK(id=1), password_hash TEXT NOT NULL,
          session_version TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS attempt_window ON attempts(team_id, attempted_at);
        CREATE INDEX IF NOT EXISTS finished_order ON teams(game_id, finished_at);
        ''')
        columns = {row['name'] for row in db.execute('PRAGMA table_info(games)')}
        if 'recovery_hash' not in columns:
            db.execute('ALTER TABLE games ADD COLUMN recovery_hash TEXT')
        if 'incident_prompt' not in columns:
            db.execute('ALTER TABLE games ADD COLUMN incident_prompt TEXT')
        db.execute('UPDATE games SET incident_prompt=? WHERE incident_prompt IS NULL OR incident_prompt="" OR incident_prompt=?',
                   (DEFAULT_INCIDENT_PROMPT, PREVIOUS_DEFAULT_INCIDENT_PROMPT))
        team_columns = {row['name'] for row in db.execute('PRAGMA table_info(teams)')}
        if 'code_encrypted' not in team_columns:
            db.execute('ALTER TABLE teams ADD COLUMN code_encrypted TEXT')
        auth = db.execute('SELECT id FROM instructor_auth WHERE id=1').fetchone()
        if auth is None and INSTRUCTOR_PASSWORD:
            db.execute('INSERT INTO instructor_auth(id,password_hash,session_version) VALUES(1,?,?)',
                       (generate_password_hash(INSTRUCTOR_PASSWORD, method='pbkdf2:sha256'), secrets.token_urlsafe(32)))


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
        version = session.get('instructor_version')
        if not version:
            return redirect(url_for('instructor_login', next=request.path))
        with connect() as db:
            auth = db.execute('SELECT session_version FROM instructor_auth WHERE id=1').fetchone()
        if not auth or not hmac.compare_digest(version, auth['session_version']):
            session.pop('instructor_version', None)
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
                                submitted = request.form.get('recovery_code', '').strip()
                                if 1 <= len(submitted) <= 64 and game['recovery_hash'] and check_password_hash(game['recovery_hash'], submitted):
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
                               response_saved=response_saved, incident_prompt=game['incident_prompt'] or DEFAULT_INCIDENT_PROMPT)


@app.route('/team/logout', methods=['POST'])
def team_logout():
    session.pop('team_id', None)
    return redirect(url_for('team_entry'))


@app.route('/instructor/login', methods=['GET', 'POST'])
def instructor_login():
    error = None
    if request.method == 'POST':
        with connect() as db:
            auth = db.execute('SELECT password_hash,session_version FROM instructor_auth WHERE id=1').fetchone()
        if not auth:
            return render_template('login.html', error='Set INSTRUCTOR_PASSWORD in the server environment, then restart the app to initialize instructor access.'), 503
        if check_password_hash(auth['password_hash'], request.form.get('password', '')):
            session['instructor_version'] = auth['session_version']
            return redirect(request.args.get('next') or url_for('instructor'))
        error = 'Password did not match.'
    elif not INSTRUCTOR_PASSWORD:
        with connect() as db:
            auth = db.execute('SELECT id FROM instructor_auth WHERE id=1').fetchone()
        if not auth:
            return render_template('login.html', error='Set INSTRUCTOR_PASSWORD in the server environment, then restart the app to initialize instructor access.'), 503
    return render_template('login.html', error=error)


@app.route('/instructor/logout', methods=['POST'])
def instructor_logout():
    session.pop('instructor_version', None)
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
            if action == 'change_password':
                auth = db.execute('SELECT password_hash FROM instructor_auth WHERE id=1').fetchone()
                current_password = request.form.get('current_password', '')
                new_password = request.form.get('new_password', '')
                confirm_password = request.form.get('confirm_password', '')
                if not auth or not check_password_hash(auth['password_hash'], current_password):
                    notice = 'Current password is incorrect.'
                elif len(new_password) < 12:
                    notice = 'Choose a new password with at least 12 characters.'
                elif new_password != confirm_password:
                    notice = 'The new passwords do not match.'
                else:
                    new_version = secrets.token_urlsafe(32)
                    new_hash = generate_password_hash(new_password, method='pbkdf2:sha256')
                    db.execute('UPDATE instructor_auth SET password_hash=?,session_version=? WHERE id=1', (new_hash, new_version))
                    session['instructor_version'] = new_version
                    notice = 'Instructor password changed. Other instructor sessions have been signed out.'
            elif action == 'new_game':
                # Starting a new session deletes all previous class data and creates a fresh game.
                confirmed = request.form.get('confirm_reset') == 'yes'
                if not confirmed:
                    notice = 'Confirm the reset checkbox to create a fresh session and delete the previous class results.'
                else:
                    names = [line.strip()[:40] for line in request.form.get('team_names', '').splitlines() if line.strip()]
                    recovery_code = request.form.get('recovery_code', '').strip()
                    incident_prompt = request.form.get('incident_prompt', '').strip()[:2000]
                    if not names:
                        notice = 'Enter at least one team name, with one team per line.'
                    elif len(names) > 100 or len(set(name.casefold() for name in names)) != len(names):
                        notice = 'Use up to 100 unique team names.'
                    elif not recovery_code or len(recovery_code) > 64:
                        notice = 'Enter a recovery code from 1 to 64 characters.'
                    elif not incident_prompt:
                        notice = 'Enter the final incident question.'
                    else:
                        with write_lock:
                            db.execute('BEGIN IMMEDIATE')
                            db.execute('DELETE FROM games')
                            cur = db.execute("INSERT INTO games(status,created_at,recovery_hash,incident_prompt) VALUES('ready',?,?,?)",
                                             (now(), generate_password_hash(recovery_code, method='pbkdf2:sha256'), incident_prompt))
                            gid = cur.lastrowid
                            codes = []
                            for name in names:
                                code = secrets.token_urlsafe(6).replace('-', '').replace('_', '').upper()[:8]
                                while code in codes:
                                    code = secrets.token_urlsafe(6).replace('-', '').replace('_', '').upper()[:8]
                                codes.append(code)
                                encrypted_code = access_code_cipher().encrypt(code.encode('utf-8')).decode('ascii')
                                db.execute('INSERT INTO teams(game_id,name,code_hash,code_encrypted) VALUES(?,?,?,?)',
                                           (gid, name, team_code_hash(code), encrypted_code))
                            db.execute('COMMIT')
                        session['issued_codes'] = list(zip(names, codes))
                        return redirect(url_for('instructor'))
            elif game:
                if action == 'update_incident_prompt':
                    incident_prompt = request.form.get('incident_prompt', '').strip()[:2000]
                    if not incident_prompt:
                        notice = 'Enter the final incident question.'
                    else:
                        db.execute('UPDATE games SET incident_prompt=? WHERE id=?', (incident_prompt, game['id']))
                        notice = 'Final incident question updated.'
                elif action == 'add_team':
                    name = request.form.get('team_name', '').strip()[:40]
                    existing = db.execute('SELECT id FROM teams WHERE game_id=? AND name=? COLLATE NOCASE',
                                          (game['id'], name)).fetchone() if name else None
                    count = db.execute('SELECT COUNT(*) FROM teams WHERE game_id=?', (game['id'],)).fetchone()[0]
                    if not name:
                        notice = 'Enter a team name.'
                    elif existing:
                        notice = 'A team with that name already exists in this session.'
                    elif count >= 100:
                        notice = 'A session can have up to 100 teams.'
                    else:
                        code = secrets.token_urlsafe(6).replace('-', '').replace('_', '').upper()[:8]
                        encrypted_code = access_code_cipher().encrypt(code.encode('utf-8')).decode('ascii')
                        db.execute('INSERT INTO teams(game_id,name,code_hash,code_encrypted) VALUES(?,?,?,?)',
                                   (game['id'], name, team_code_hash(code), encrypted_code))
                        session['issued_codes'] = [(name, code)]
                        notice = f"Team {name} was added. Share its access code privately."
                elif action == 'delete_team':
                    team_id = request.form.get('team_id', type=int)
                    team = db.execute('SELECT id,name FROM teams WHERE id=? AND game_id=?', (team_id, game['id'])).fetchone()
                    if team:
                        db.execute('DELETE FROM teams WHERE id=? AND game_id=?', (team['id'], game['id']))
                        notice = f"Team {team['name']} and its completion data were deleted."
                    else:
                        notice = 'Team not found in the current session.'
                elif action == 'regenerate_code':
                    team_id = request.form.get('team_id', type=int)
                    team = db.execute('SELECT id,name FROM teams WHERE id=? AND game_id=?', (team_id, game['id'])).fetchone()
                    if team:
                        code = secrets.token_urlsafe(6).replace('-', '').replace('_', '').upper()[:8]
                        encrypted_code = access_code_cipher().encrypt(code.encode('utf-8')).decode('ascii')
                        db.execute('UPDATE teams SET code_hash=?,code_encrypted=? WHERE id=? AND game_id=?',
                                   (team_code_hash(code), encrypted_code, team['id'], game['id']))
                        session['issued_codes'] = [(team['name'], code)]
                        notice = f"A replacement access code was created for {team['name']}."
                    else:
                        notice = 'Team not found in the current session.'
                elif action == 'start' and game['status'] in ('ready', 'paused'):
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
        access_codes = []
        if game:
            rows = db.execute('SELECT id,name,code_encrypted FROM teams WHERE game_id=? ORDER BY name COLLATE NOCASE',
                              (game['id'],)).fetchall()
            for row in rows:
                code = None
                if row['code_encrypted']:
                    try:
                        code = access_code_cipher().decrypt(row['code_encrypted'].encode('ascii')).decode('utf-8')
                    except (InvalidToken, UnicodeDecodeError):
                        code = None
                access_codes.append({'id': row['id'], 'name': row['name'], 'code': code})
        return render_template('instructor.html', game=game, teams=teams, timer=duration_label(elapsed(game)) if game else '00:00',
                               notice=notice, issued_codes=issued_codes, access_codes=access_codes)


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
