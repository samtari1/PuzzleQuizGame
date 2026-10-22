import hashlib
import hmac
import base64
import json
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
from quiz_data import QUIZ_QUESTIONS

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_urlsafe(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax',
                  SESSION_COOKIE_SECURE=os.environ.get('APP_ENV') == 'production')
app.config['MAX_CONTENT_LENGTH'] = 512 * 1024
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
        if 'questions_json' not in columns:
            db.execute('ALTER TABLE games ADD COLUMN questions_json TEXT')
        db.execute('UPDATE games SET incident_prompt=? WHERE incident_prompt IS NULL OR incident_prompt="" OR incident_prompt=?',
                   (DEFAULT_INCIDENT_PROMPT, PREVIOUS_DEFAULT_INCIDENT_PROMPT))
        db.execute('UPDATE games SET questions_json=? WHERE questions_json IS NULL OR questions_json=""',
                   (json.dumps(QUIZ_QUESTIONS, ensure_ascii=False),))
        team_columns = {row['name'] for row in db.execute('PRAGMA table_info(teams)')}
        if 'code_encrypted' not in team_columns:
            db.execute('ALTER TABLE teams ADD COLUMN code_encrypted TEXT')
        if 'question_index' not in team_columns:
            db.execute('ALTER TABLE teams ADD COLUMN question_index INTEGER NOT NULL DEFAULT 0')
        if 'penalty_seconds' not in team_columns:
            db.execute('ALTER TABLE teams ADD COLUMN penalty_seconds INTEGER NOT NULL DEFAULT 0')
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


def normalize_question_bank(payload):
    if isinstance(payload, dict):
        payload = payload.get('questions')
    if not isinstance(payload, list) or not 1 <= len(payload) <= 100:
        raise ValueError('The file must contain between 1 and 100 questions.')
    normalized = []
    for number, item in enumerate(payload, 1):
        if not isinstance(item, dict):
            raise ValueError(f'Question {number} must be an object.')
        prompt = item.get('question')
        title = item.get('title') or f'Question {number}'
        options = item.get('options', item.get('choices'))
        answer = item.get('answer')
        if not isinstance(prompt, str) or not prompt.strip() or len(prompt.strip()) > 2000:
            raise ValueError(f'Question {number} needs question text (up to 2,000 characters).')
        if not isinstance(title, str) or not title.strip() or len(title.strip()) > 100:
            raise ValueError(f'Question {number} needs a title (up to 100 characters).')
        if isinstance(options, dict):
            labels = sorted(options.keys())
            if labels != [chr(ord('A') + i) for i in range(len(labels))]:
                raise ValueError(f'Question {number} choices must be labeled consecutively from A.')
            options = [options[label] for label in labels]
        if (not isinstance(options, list) or not 2 <= len(options) <= 6
                or any(not isinstance(option, str) or not option.strip() or len(option.strip()) > 500 for option in options)):
            raise ValueError(f'Question {number} needs 2 to 6 non-empty answer choices.')
        if isinstance(answer, str):
            answer = ord(answer.strip().upper()) - ord('A') if len(answer.strip()) == 1 else -1
        if not isinstance(answer, int) or isinstance(answer, bool) or not 0 <= answer < len(options):
            raise ValueError(f'Question {number} answer must be a choice letter such as A, B, C, or D.')
        normalized.append({'title': title.strip(), 'question': prompt.strip(),
                           'options': [option.strip() for option in options], 'answer': answer})
    return normalized


def questions_for_game(game):
    try:
        return normalize_question_bank(json.loads(game['questions_json']))
    except (ValueError, TypeError, json.JSONDecodeError):
        return QUIZ_QUESTIONS


def question_bank_for_editor(questions):
    return {'questions': [
        {'title': item['title'], 'question': item['question'], 'options': item['options'],
         'answer': chr(ord('A') + item['answer'])}
        for item in questions
    ]}


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
    selected_choice = None
    with connect() as db:
        game = current_game(db)
        if game is None:
            return render_template('team.html', game_ready=False, question_count=0)
        questions = questions_for_game(game)
        team = None
        if request.method == 'POST':
            action = request.form.get('action', 'login')
            if action == 'response':
                team = db.execute('SELECT * FROM teams WHERE id=? AND game_id=?',
                                  (session.get('team_id'), game['id'])).fetchone()
                if not team or not team['finished_at']:
                    message = 'Complete the questions before sending your response.'
                else:
                    text = request.form.get('response', '').strip()[:2000]
                    db.execute('UPDATE teams SET response=? WHERE id=? AND game_id=?',
                               (text, team['id'], game['id']))
                    response_saved = True
                    success = True
                    completed_time = duration_label(team['elapsed'])
                    message = 'Your response has been saved.'
            elif action == 'answer':
                team = db.execute('SELECT * FROM teams WHERE id=? AND game_id=?',
                                  (session.get('team_id'), game['id'])).fetchone()
                selected_choice = request.form.get('choice', type=int)
                submitted_question_index = request.form.get('question_index', type=int)
                if not team:
                    session.pop('team_id', None)
                    message = 'Enter your team details to continue.'
                elif team['finished_at']:
                    success = True
                    completed_time = duration_label(team['elapsed'])
                elif game['status'] != 'running':
                    message = 'The instructor has paused the challenge.'
                else:
                    with write_lock:
                        db.execute('BEGIN IMMEDIATE')
                        current = db.execute('SELECT * FROM teams WHERE id=? AND game_id=?',
                                             (team['id'], game['id'])).fetchone()
                        if current['finished_at']:
                            success = True
                            completed_time = duration_label(current['elapsed'])
                        elif game['status'] != 'running':
                            message = 'The instructor has paused the challenge.'
                        elif submitted_question_index != current['question_index']:
                            message = 'Your team has moved to a different question. Review the current question below.'
                            selected_choice = None
                        else:
                            cutoff = now() - GUESS_WINDOW
                            db.execute('DELETE FROM attempts WHERE team_id=? AND attempted_at<?',
                                       (team['id'], cutoff))
                            count = db.execute('SELECT COUNT(*) FROM attempts WHERE team_id=?',
                                               (team['id'],)).fetchone()[0]
                            if count >= GUESS_LIMIT:
                                message = 'Too many attempts. Please wait a minute before trying again.'
                            else:
                                db.execute('INSERT INTO attempts(team_id,attempted_at) VALUES(?,?)',
                                           (team['id'], now()))
                                question_index = current['question_index']
                                if (0 <= question_index < len(questions)
                                        and selected_choice == questions[question_index]['answer']):
                                    next_index = question_index + 1
                                    if next_index == len(questions):
                                        stamp = now()
                                        fresh_game = db.execute('SELECT * FROM games WHERE id=?',
                                                               (game['id'],)).fetchone()
                                        penalty = db.execute('SELECT penalty_seconds FROM teams WHERE id=?',
                                                             (team['id'],)).fetchone()['penalty_seconds']
                                        team_elapsed = elapsed(fresh_game, stamp) + penalty
                                        db.execute('UPDATE teams SET question_index=?,finished_at=?,elapsed=? '
                                                   'WHERE id=? AND finished_at IS NULL',
                                                   (next_index, stamp, team_elapsed, team['id']))
                                        success = True
                                        completed_time = duration_label(team_elapsed)
                                        message = 'Correct! You completed all questions.'
                                    else:
                                        db.execute('UPDATE teams SET question_index=? '
                                                   'WHERE id=? AND finished_at IS NULL',
                                                   (next_index, team['id']))
                                        message = 'Correct! Moving to the next question.'
                                    selected_choice = None
                                else:
                                    db.execute('UPDATE teams SET penalty_seconds=penalty_seconds+60 '
                                               'WHERE id=? AND finished_at IS NULL', (team['id'],))
                                    message = 'Incorrect—1 minute added to your time. Try again.'
                        db.execute('COMMIT')
                    team = db.execute('SELECT * FROM teams WHERE id=? AND game_id=?',
                                      (team['id'], game['id'])).fetchone()
                    if team and team['finished_at']:
                        success = True
                        if completed_time is None:
                            completed_time = duration_label(team['elapsed'])
            else:
                access_code = request.form.get('access_code', '').strip().upper()
                entered_name = request.form.get('team_name', '').strip()[:40]
                if len(access_code) < 6 or len(access_code) > 12 or not access_code.isalnum():
                    message = 'Enter the team access code provided by your instructor.'
                else:
                    team = db.execute('SELECT * FROM teams WHERE game_id=? AND code_hash=?',
                                      (game['id'], team_code_hash(access_code))).fetchone()
                    if not team or not hmac.compare_digest(team['name'].casefold(), entered_name.casefold()):
                        message = 'Team details not recognized.'
                    else:
                        session['team_id'] = team['id']
                        if team['finished_at']:
                            success = True
                            completed_time = duration_label(team['elapsed'])
                        elif game['status'] != 'running':
                            message = 'Your team is ready. The instructor will start the challenge shortly.'
            if success and team:
                team = db.execute('SELECT * FROM teams WHERE id=? AND game_id=?',
                                  (team['id'], game['id'])).fetchone()
        elif session.get('team_id'):
            team = db.execute('SELECT * FROM teams WHERE id=? AND game_id=?',
                              (session['team_id'], game['id'])).fetchone()
            if not team:
                session.pop('team_id', None)
            elif team['finished_at']:
                success = True
                completed_time = duration_label(team['elapsed'])

        question = None
        team_time = None
        if team and not success and 0 <= team['question_index'] < len(questions):
            item = questions[team['question_index']]
            # Never send the correct answer index to the browser.
            question = {'number': team['question_index'] + 1, 'total': len(questions),
                        'title': item['title'], 'text': item['question'], 'options': item['options']}
        if team:
            team_time = (team['elapsed'] if team['finished_at'] else
                         elapsed(game) + (team['penalty_seconds'] or 0))
        return render_template('team.html', game_ready=True, game_status=game['status'], message=message,
                               success=success, completed_time=completed_time, team=team, question=question,
                               selected_choice=selected_choice, response_saved=response_saved,
                               team_time=duration_label(team_time or 0),
                               penalty_time=duration_label(team['penalty_seconds'] or 0) if team else '00:00',
                               question_count=len(questions),
                               incident_prompt=game['incident_prompt'] or DEFAULT_INCIDENT_PROMPT)


@app.route('/team/logout', methods=['POST'])
def team_logout():
    session.pop('team_id', None)
    return redirect(url_for('team_entry'))


@app.route('/api/team-time')
def team_time_api():
    team_id = session.get('team_id')
    if not team_id:
        return jsonify({'active': False}), 401
    with connect() as db:
        game = current_game(db)
        team = db.execute('SELECT * FROM teams WHERE id=? AND game_id=?',
                          (team_id, game['id'] if game else -1)).fetchone()
        if not team:
            return jsonify({'active': False}), 404
        used = team['elapsed'] if team['finished_at'] else elapsed(game) + (team['penalty_seconds'] or 0)
        return jsonify({'active': True, 'status': game['status'],
                        'used': duration_label(used),
                        'penalty': duration_label(team['penalty_seconds'] or 0)})


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
                    incident_prompt = request.form.get('incident_prompt', '').strip()[:2000]
                    if not names:
                        notice = 'Enter at least one team name, with one team per line.'
                    elif len(names) > 100 or len(set(name.casefold() for name in names)) != len(names):
                        notice = 'Use up to 100 unique team names.'
                    elif not incident_prompt:
                        notice = 'Enter the final incident question.'
                    else:
                        with write_lock:
                            db.execute('BEGIN IMMEDIATE')
                            db.execute('DELETE FROM games')
                            cur = db.execute("INSERT INTO games(status,created_at,incident_prompt,questions_json) VALUES('ready',?,?,?)",
                                             (now(), incident_prompt, json.dumps(QUIZ_QUESTIONS, ensure_ascii=False)))
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
                if action == 'update_questions':
                    if game['status'] != 'ready':
                        notice = 'Questions can only be changed before the instructor starts the timer.'
                    else:
                        question_file = request.files.get('question_file')
                        try:
                            if question_file and question_file.filename:
                                payload = json.loads(question_file.read().decode('utf-8-sig'))
                            else:
                                payload = json.loads(request.form.get('questions_json', ''))
                            question_bank = normalize_question_bank(payload)
                            db.execute('UPDATE games SET questions_json=? WHERE id=?',
                                       (json.dumps(question_bank, ensure_ascii=False), game['id']))
                            notice = f"Saved {len(question_bank)} questions for this session."
                        except (ValueError, TypeError, UnicodeDecodeError) as error:
                            notice = f'Questions were not saved: {error}'
                elif action == 'update_incident_prompt':
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
        question_editor_json = json.dumps(
            question_bank_for_editor(questions_for_game(game)), ensure_ascii=False, indent=2
        ) if game else ''
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
                               notice=notice, issued_codes=issued_codes, access_codes=access_codes,
                               question_editor_json=question_editor_json,
                               question_count=len(questions_for_game(game)) if game else len(QUIZ_QUESTIONS))


@app.route('/instructor/question-template')
@instructor_required
def instructor_question_template():
    payload = question_bank_for_editor(QUIZ_QUESTIONS)
    return app.response_class(
        json.dumps(payload, ensure_ascii=False, indent=2),
        mimetype='application/json',
        headers={'Content-Disposition': 'attachment; filename=ict_industry_questions.json'}
    )


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
