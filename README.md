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

`deploy.sh` runs on the VPS. It fetches the latest `main` branch from `https://github.com/samtari1/PuzzleQuizGame`, resets the app checkout to `origin/main`, installs dependencies, and restarts the systemd service. The environment file and SQLite database live outside the checkout.

This setup assumes Ubuntu 22.04 or newer, a domain pointed at the VPS, and SSH access.

### Prepare the VPS once

Connect over SSH and install the packages and create the app and data directories:

```sh
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip apache2 certbot python3-certbot-apache
sudo useradd --system --user-group --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin ict-escape
sudo mkdir -p /var/lib/ict-escape /etc/ict-escape
sudo chown ict-escape:ict-escape /var/lib/ict-escape
sudo git clone --branch main https://github.com/samtari1/PuzzleQuizGame.git /var/www/PuzzleQuizGame
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

### Deploy or update

On the VPS, run:

```sh
sudo /var/www/PuzzleQuizGame/deploy.sh
```

To fetch changes and preview the commits that would be deployed without changing the checkout or restarting the app:

```sh
sudo /var/www/PuzzleQuizGame/deploy.sh --dry-run
```

The deployment script resets tracked app files to the latest `origin/main`, installs Python requirements, installs/updates the systemd service, and restarts it. It does not include `.env`, the virtual environment, or the database in Git. Keep any manual server configuration in `/etc/ict-escape` and `/var/lib/ict-escape`, outside the checkout.

If the GitHub repository is private, configure a read-only deploy key for the VPS root account and create `/etc/ict-escape/deploy.conf` with its SSH clone URL:

```sh
sudo sh -c 'printf "%s\n" "REPO_URL=git@github.com:samtari1/PuzzleQuizGame.git" > /etc/ict-escape/deploy.conf'
sudo chmod 600 /etc/ict-escape/deploy.conf
```

### Configure the domain and HTTPS once

At your DNS provider, create an A record with host `puzzle` pointing to your VPS IPv4 address. Add an AAAA record only if the VPS has a working public IPv6 address. Wait for DNS to resolve, then enable Apache's proxy modules and install the virtual host:

```sh
sudo a2enmod proxy proxy_http
sudo cp /var/www/PuzzleQuizGame/deploy/apache-puzzle.example /etc/apache2/sites-available/puzzle-ict-escape.conf
sudo a2ensite puzzle-ict-escape.conf
sudo apache2ctl configtest
sudo systemctl reload apache2
sudo certbot --apache -d puzzle.dryangai.com
```

Allow inbound TCP ports 80 and 443 in the VPS firewall/security group. Apache forwards requests to Gunicorn on `127.0.0.1:8000`. After DNS has propagated and HTTPS is active, open `https://puzzle.dryangai.com`. Certbot configures certificate renewal; check it with `sudo certbot renew --dry-run`.

Check app status and logs with `sudo systemctl status ict-escape` and `sudo journalctl -u ict-escape -f`. Back up `/var/lib/ict-escape/game.db` regularly. Keep one Gunicorn worker while using SQLite on local disk.
