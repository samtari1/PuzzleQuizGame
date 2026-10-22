# ICT Industry Escape Challenge

A small classroom game app built with Flask, SQLite, HTML, CSS, and vanilla JavaScript. It uses server-side validation for the recovery code, stores only hashed team access codes, and exposes only finished team names and times to the public scoreboard.

## Run locally

Requires Python 3.9 or newer. From the project folder, run:

```sh
./setup.sh
```

Edit the created `.env` and replace the sample `FLASK_SECRET_KEY` and `INSTRUCTOR_PASSWORD` values. Then start the app:

```sh
./start.sh
```

Open <http://localhost:5000>. Stop the server with **Ctrl+C**. `setup.sh` creates `.venv`, installs the dependencies, creates `.env` if needed, and initializes the SQLite database. `start.sh` loads `.env` and launches the app. The app creates `game.db` on first launch. Set the five-digit recovery code when creating each game session in instructor controls; the app stores only a password hash of it. Keep `FLASK_SECRET_KEY` stable between restarts so instructor sessions remain signed in. The instructor password is read from `INSTRUCTOR_PASSWORD` and is never stored in the database.

## Classroom setup

1. Open `/instructor` and sign in with `INSTRUCTOR_PASSWORD`.
2. Enter one team name per line, set the five-digit recovery code for the printed puzzles, and create a fresh session. Confirm the reset checkbox. The app replaces the previous session and its results.
3. Copy or print the one-time access code list and give each code privately to its team. Codes are stored as SHA-256 hashes; after leaving the page, the original codes cannot be retrieved. Create a new session to issue replacements.
4. Project `/scoreboard` on the classroom display. Teams use `/team` on their own devices.
5. Start the timer in instructor controls. Teams submit their access code and five-digit recovery code. Incorrect guesses are rate-limited and never appear on the scoreboard.
6. After success, teams submit their response to the Canvas notice incident prompt. Review or edit responses in instructor controls.
7. For another class, use **Start over for another class**, enter its team names, and confirm deletion. This removes the prior session, access codes, completion times, and responses.

The timer starts/resumes and pauses using server timestamps. Completion time is measured from the current session timer; the server timestamp determines the finish order.

## Deploy

The included `Procfile` works with hosts that support a Python web process. Install dependencies with `pip install -r requirements.txt`, then run:

```sh
gunicorn --workers 1 --bind 0.0.0.0:${PORT:-5000} app:app
```

Configure `INSTRUCTOR_PASSWORD`, a long random `FLASK_SECRET_KEY`, and `APP_ENV=production` as server environment variables. The production setting marks the signed session cookie secure, so serve the app over HTTPS. Set `DATABASE_PATH` to a persistent writable disk path on the host; the default `game.db` is in the app directory and may be ephemeral on some hosts. Use HTTPS through the host's TLS proxy. Keep one Gunicorn worker when using the bundled SQLite database on local disk; use a persistent shared database setup before scaling horizontally. The app does not require paid services.

`/healthz` provides a simple health check. `requirements.txt`, `Procfile`, and `.env.example` provide the basic deployment files.

## Deploy to an Ubuntu VPS

The included `deploy.sh` uploads the current app, installs dependencies, installs/updates the systemd service, and restarts it. The steps below prepare an Ubuntu 22.04+ VPS once; after that, deployments are one command. This setup uses Nginx and Certbot for HTTPS and keeps SQLite on persistent disk.

### Prepare the VPS once

Connect over SSH, then install the packages and create the app and data directories:

```sh
sudo apt update
sudo apt install -y python3 python3-venv python3-pip nginx certbot python3-certbot-nginx rsync
sudo useradd --system --user-group --create-home --home-dir /opt/ict-escape --shell /usr/sbin/nologin ict-escape
sudo mkdir -p /var/lib/ict-escape /etc/ict-escape
sudo chown ict-escape:ict-escape /var/lib/ict-escape
```

Create `/etc/ict-escape/ict-escape.env` on the VPS with strong, unique secrets. Run this once; save the generated instructor password securely:

```sh
sudo sh -c 'cat > /etc/ict-escape/ict-escape.env <<EOF
APP_ENV=production
FLASK_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
INSTRUCTOR_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))")
DATABASE_PATH=/var/lib/ict-escape/game.db
EOF'
sudo chmod 600 /etc/ict-escape/ict-escape.env
```

The five-digit recovery code is set in instructor controls whenever you create a session.

### Deploy or update the app

From the project folder on your computer, run this with your SSH user and VPS host or IP:

```sh
DEPLOY_HOST=YOUR_SSH_USER@YOUR_VPS ./deploy.sh
```

The SSH account must have sudo access. To preview the files that would be uploaded, use:

```sh
DEPLOY_HOST=YOUR_SSH_USER@YOUR_VPS ./deploy.sh --dry-run
```

The script excludes `.env`, `.venv`, local databases, and cache files. It uploads to `/opt/ict-escape`, installs Python dependencies, preserves `/var/lib/ict-escape/game.db`, and restarts the app service. Make sure your SSH key is set up before running it.

### Configure the domain and HTTPS once

Point your domain's DNS A record to the VPS IP (and AAAA record too if IPv6 is configured). From the project folder, copy the Nginx example to the VPS:

```sh
scp deploy/nginx-ict-escape.example YOUR_SSH_USER@YOUR_VPS:/tmp/nginx-ict-escape
```

On the VPS, replace `your-domain.example` with your actual domain, enable the config, and request a certificate:

```sh
sudo sed 's/your-domain.example/your-real-domain.example/g' /tmp/nginx-ict-escape | sudo tee /etc/nginx/sites-available/ict-escape >/dev/null
sudo ln -s /etc/nginx/sites-available/ict-escape /etc/nginx/sites-enabled/ict-escape
sudo nginx -t
sudo systemctl reload nginx
sudo certbot --nginx -d your-real-domain.example
```

Allow inbound TCP ports 80 and 443 in the VPS firewall/security group. After DNS has propagated and HTTPS is active, open `https://your-real-domain.example`. Certbot configures certificate renewal; check it with `sudo certbot renew --dry-run`.

Check app status and logs with `sudo systemctl status ict-escape` and `sudo journalctl -u ict-escape -f`. Back up `/var/lib/ict-escape/game.db` regularly. Keep one Gunicorn worker while using SQLite on local disk.
# PuzzleQuizGame
