import os
import sqlite3
from pathlib import Path
from threading import Lock
from urllib.parse import urlparse
from werkzeug.security import generate_password_hash, check_password_hash

from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from proxy_runtime import start_proxy_server

app = Flask(__name__)
app.secret_key = "secretkey"
DATA_DIR = Path(os.environ.get("LOCALAPPDATA", app.root_path)) / "CyberProxyDefender"
DATABASE = DATA_DIR / "users.db"
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8888
PROXY_PUBLIC_IP = "127.0.0.1"
proxy_thread = None
proxy_lock = Lock()


def ensure_data_dir():
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def get_db():
    ensure_data_dir()
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


def ensure_column(db, table_name, column_name, definition):
    columns = {row[1] for row in db.execute(f"PRAGMA table_info({table_name})").fetchall()}
    if column_name not in columns:
        db.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}")


def init_db():
    ensure_data_dir()
    db = sqlite3.connect(DATABASE)
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            url TEXT NOT NULL,
            method TEXT NOT NULL DEFAULT 'GET',
            protocol TEXT NOT NULL DEFAULT 'HTTPS',
            status TEXT NOT NULL CHECK(status IN ('Allowed', 'Blocked')),
            threat_level TEXT NOT NULL DEFAULT 'Low',
            bandwidth_kb INTEGER NOT NULL DEFAULT 0,
            requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    ensure_column(db, "logs", "client_ip", "TEXT NOT NULL DEFAULT '0.0.0.0'")
    ensure_column(db, "logs", "proxy_ip", f"TEXT NOT NULL DEFAULT '{PROXY_PUBLIC_IP}'")
    ensure_column(db, "logs", "website_domain", "TEXT NOT NULL DEFAULT ''")
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS blocked_sites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT UNIQUE NOT NULL,
            reason TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    db.commit()
    seed_demo_data(db)
    db.close()


def seed_demo_data(db):
    db.execute(
        """
        UPDATE logs
        SET client_ip = COALESCE(NULLIF(client_ip, ''), '127.0.0.1'),
            proxy_ip = COALESCE(NULLIF(proxy_ip, ''), ?),
            website_domain = CASE
                WHEN website_domain IS NULL OR website_domain = '' THEN
                    REPLACE(REPLACE(REPLACE(url, 'https://', ''), 'http://', ''), '/', '')
                ELSE website_domain
            END
        """,
        (PROXY_PUBLIC_IP,),
    )
    user_count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if user_count == 0:
        db.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            ("admin", hash_password("admin123")),
        )

    blocked_count = db.execute("SELECT COUNT(*) FROM blocked_sites").fetchone()[0]
    if blocked_count == 0:
        db.executemany(
            "INSERT INTO blocked_sites (url, reason) VALUES (?, ?)",
            [
                ("malware-example.net", "Malware distribution"),
                ("phishing-alert.org", "Phishing campaign"),
                ("social-media.local", "Restricted during work hours"),
                ("torrent-mirror.cc", "Unauthorized content sharing"),
                ("unknown-downloads.xyz", "Suspicious downloads"),
            ],
        )

    logs_count = db.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
    if logs_count == 0:
        db.executemany(
            """
            INSERT INTO logs (
                username, url, method, protocol, status, threat_level, bandwidth_kb, requested_at, client_ip, proxy_ip, website_domain
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                ("admin", "https://intranet.company.local", "GET", "HTTPS", "Allowed", "Low", 320, "2026-04-10 08:15:00", "192.168.0.11", PROXY_PUBLIC_IP, "intranet.company.local"),
                ("admin", "https://mail.securehub.com", "POST", "HTTPS", "Allowed", "Low", 540, "2026-04-10 08:22:00", "192.168.0.11", PROXY_PUBLIC_IP, "mail.securehub.com"),
                ("admin", "http://malware-example.net/payload", "GET", "HTTP", "Blocked", "High", 0, "2026-04-10 08:29:00", "192.168.0.11", PROXY_PUBLIC_IP, "malware-example.net"),
                ("admin", "https://analytics.cloudsuite.io", "GET", "HTTPS", "Allowed", "Low", 410, "2026-04-10 09:02:00", "192.168.0.11", PROXY_PUBLIC_IP, "analytics.cloudsuite.io"),
                ("admin", "https://phishing-alert.org/login", "POST", "HTTPS", "Blocked", "Critical", 0, "2026-04-10 09:11:00", "192.168.0.11", PROXY_PUBLIC_IP, "phishing-alert.org"),
                ("auditor", "https://docs.python.org", "GET", "HTTPS", "Allowed", "Low", 680, "2026-04-10 09:45:00", "192.168.0.23", PROXY_PUBLIC_IP, "docs.python.org"),
                ("auditor", "https://social-media.local/feed", "GET", "HTTPS", "Blocked", "Medium", 0, "2026-04-10 10:03:00", "192.168.0.23", PROXY_PUBLIC_IP, "social-media.local"),
                ("operator", "http://updates.vendor.net", "GET", "HTTP", "Allowed", "Low", 220, "2026-04-10 10:16:00", "192.168.0.31", PROXY_PUBLIC_IP, "updates.vendor.net"),
                ("operator", "https://unknown-downloads.xyz/setup", "GET", "HTTPS", "Blocked", "High", 0, "2026-04-10 10:22:00", "192.168.0.31", PROXY_PUBLIC_IP, "unknown-downloads.xyz"),
                ("operator", "https://status.gateway.net", "GET", "HTTPS", "Allowed", "Low", 150, "2026-04-10 10:38:00", "192.168.0.31", PROXY_PUBLIC_IP, "status.gateway.net"),
                ("admin", "https://reports.internal", "GET", "HTTPS", "Allowed", "Low", 490, "2026-04-10 11:05:00", "192.168.0.11", PROXY_PUBLIC_IP, "reports.internal"),
                ("admin", "http://torrent-mirror.cc/file.iso", "GET", "HTTP", "Blocked", "High", 0, "2026-04-10 11:18:00", "192.168.0.11", PROXY_PUBLIC_IP, "torrent-mirror.cc"),
            ],
        )
    db.commit()


def get_overview_data():
    db = get_db()
    total_users = db.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"]
    total_requests = db.execute("SELECT COUNT(*) AS count FROM logs").fetchone()["count"]
    blocked_requests = db.execute(
        "SELECT COUNT(*) AS count FROM logs WHERE status = 'Blocked'"
    ).fetchone()["count"]
    blocked_sites = db.execute("SELECT COUNT(*) AS count FROM blocked_sites").fetchone()["count"]
    latest_users = db.execute(
        "SELECT username, created_at FROM users ORDER BY id DESC LIMIT 5"
    ).fetchall()

    stats = {
        "total_requests": total_requests,
        "blocked_requests": blocked_requests,
        "active_users": total_users,
        "blocked_sites": blocked_sites,
    }
    return stats, latest_users


def get_traffic_data():
    db = get_db()
    protocol_rows = db.execute(
        """
        SELECT protocol, COUNT(*) AS request_count, COALESCE(SUM(bandwidth_kb), 0) AS bandwidth_kb
        FROM logs
        GROUP BY protocol
        ORDER BY request_count DESC
        """
    ).fetchall()
    top_destinations = db.execute(
        """
        SELECT url, status, COUNT(*) AS hits, COALESCE(SUM(bandwidth_kb), 0) AS bandwidth_kb
        FROM logs
        GROUP BY url, status
        ORDER BY hits DESC, bandwidth_kb DESC
        LIMIT 6
        """
    ).fetchall()
    traffic_feed_rows = db.execute(
        """
        SELECT
            username,
            client_ip,
            proxy_ip,
            url,
            website_domain,
            method,
            protocol,
            status,
            threat_level,
            bandwidth_kb,
            requested_at,
            strftime('%H:%M:%S', requested_at) AS request_time
        FROM logs
        ORDER BY requested_at DESC
        LIMIT 10
        """
    ).fetchall()
    recent_alerts = db.execute(
        """
        SELECT username, url, threat_level, requested_at
        FROM logs
        WHERE status = 'Blocked'
        ORDER BY requested_at DESC
        LIMIT 5
        """
    ).fetchall()

    total_bandwidth = sum(row["bandwidth_kb"] for row in protocol_rows)
    allowed_count = db.execute(
        "SELECT COUNT(*) AS count FROM logs WHERE status = 'Allowed'"
    ).fetchone()["count"]
    blocked_count = db.execute(
        "SELECT COUNT(*) AS count FROM logs WHERE status = 'Blocked'"
    ).fetchone()["count"]

    summary = {
        "requests_today": allowed_count + blocked_count,
        "allowed_count": allowed_count,
        "blocked_count": blocked_count,
        "bandwidth_mb": round(total_bandwidth / 1024, 2),
    }
    traffic_feed = []
    for row in traffic_feed_rows:
        client_ip = row["client_ip"]
        if not client_ip or client_ip == "0.0.0.0":
            if row["username"].startswith("client@"):
                client_ip = row["username"].split("@", 1)[1]
            else:
                client_ip = "127.0.0.1"

        website_domain = row["website_domain"] or display_host(row["url"])
        traffic_feed.append(
            {
                "client_ip": client_ip,
                "proxy_ip": row["proxy_ip"] or PROXY_PUBLIC_IP,
                "url": row["url"],
                "website_domain": website_domain,
                "method": row["method"],
                "protocol": row["protocol"],
                "status": row["status"],
                "threat_level": row["threat_level"],
                "bandwidth_kb": row["bandwidth_kb"],
                "requested_at": row["requested_at"],
                "request_time": row["request_time"],
            }
        )
    return summary, protocol_rows, top_destinations, traffic_feed, recent_alerts


def get_logs_data():
    db = get_db()
    system_logs = db.execute(
        """
        SELECT username, url, method, protocol, status, threat_level, bandwidth_kb, requested_at
        FROM logs
        ORDER BY requested_at DESC
        LIMIT 14
        """
    ).fetchall()
    blocked_activity = db.execute(
        """
        SELECT username, url, threat_level, requested_at
        FROM logs
        WHERE status = 'Blocked'
        ORDER BY requested_at DESC
        LIMIT 8
        """
    ).fetchall()
    blocked_sites = db.execute(
        """
        SELECT url, reason, created_at
        FROM blocked_sites
        ORDER BY created_at DESC, id DESC
        LIMIT 8
        """
    ).fetchall()
    activity_by_user = db.execute(
        """
        SELECT username, COUNT(*) AS total_events
        FROM logs
        GROUP BY username
        ORDER BY total_events DESC, username ASC
        LIMIT 6
        """
    ).fetchall()

    metrics = {
        "total_events": db.execute("SELECT COUNT(*) AS count FROM logs").fetchone()["count"],
        "security_alerts": db.execute(
            "SELECT COUNT(*) AS count FROM logs WHERE threat_level IN ('High', 'Critical')"
        ).fetchone()["count"],
        "blocked_events": db.execute(
            "SELECT COUNT(*) AS count FROM logs WHERE status = 'Blocked'"
        ).fetchone()["count"],
        "policy_rules": db.execute("SELECT COUNT(*) AS count FROM blocked_sites").fetchone()["count"],
    }
    return metrics, system_logs, blocked_activity, blocked_sites, activity_by_user


def display_host(url):
    parsed = urlparse(url)
    return parsed.netloc or url


def hash_password(password):
    return generate_password_hash(password)


def verify_password(stored_password, provided_password):
    if not stored_password:
        return False
    if stored_password.startswith("pbkdf2:") or stored_password.startswith("scrypt:"):
        return check_password_hash(stored_password, provided_password)
    return stored_password == provided_password


def get_current_user():
    username = session.get("user")
    if not username:
        return None
    return get_db().execute(
        "SELECT username, created_at FROM users WHERE username = ?",
        (username,),
    ).fetchone()


def ensure_proxy_server():
    global proxy_thread
    with proxy_lock:
        if proxy_thread is None or not proxy_thread.is_alive():
            proxy_thread = start_proxy_server(str(DATABASE), host=PROXY_HOST, port=PROXY_PORT)
    return proxy_thread


@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.route("/")
def home():
    return render_template("index.html", active_page="home")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        user = get_db().execute(
            "SELECT username, password FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if user and verify_password(user["password"], password):
            session["user"] = user["username"]
            return redirect(url_for("dashboard"))

        flash("Invalid username or password")

    return render_template("login.html", active_page="login")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        if not username or not password or not confirm_password:
            flash("Username and password are required")
            return render_template("register.html")

        if password != confirm_password:
            flash("Passwords do not match")
            return redirect(url_for("register"))

        db = get_db()
        existing_user = db.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if existing_user:
            flash("User already exists")
        else:
            db.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hash_password(password)),
            )
            db.commit()
            flash("Account created successfully. Please login.")
            return redirect(url_for("login"))

    return render_template("register.html", active_page="register")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form["username"].strip()
        new_password = request.form["new_password"]

        if not username or not new_password:
            flash("Username and new password are required")
            return render_template("forgot_password.html", active_page="forgot_password")

        db = get_db()
        user = db.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if not user:
            flash("User not found")
        else:
            db.execute(
                "UPDATE users SET password = ? WHERE username = ?",
                (hash_password(new_password), username),
            )
            db.commit()
            flash("Password updated successfully. Please log in.")
            return redirect(url_for("login"))

    return render_template("forgot_password.html", active_page="forgot_password")

@app.route('/change-password', methods=['POST'])
def change_password():
    if 'user' not in session:
        return redirect(url_for('login'))

    current = request.form.get('current_password')
    new = request.form.get('new_password')
    confirm = request.form.get('confirm_password')

    db = get_db()

    user = db.execute(
        'SELECT * FROM users WHERE username = ?',
        (session['user'],)
    ).fetchone()

    if not user or not verify_password(user['password'], current):
        flash("Current password is incorrect")
        return redirect(url_for('settings'))

    if not new or new != confirm:
        flash("New passwords do not match")
        return redirect(url_for('settings'))

    db.execute(
        'UPDATE users SET password = ? WHERE username = ?',
        (hash_password(new), session['user'])
    )
    db.commit()

    flash("Password updated successfully")
    return redirect(url_for('settings'))




@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))

    ensure_proxy_server()
    stats, latest_users = get_overview_data()

    return render_template(
        "dashboard.html",
        username=session["user"],
        stats=stats,
        latest_users=latest_users,
        proxy_host=PROXY_HOST,
        proxy_port=PROXY_PORT,
        active_page="dashboard",
    )


@app.route("/profile")
def profile():
    if "user" not in session:
        return redirect(url_for("login"))

    user = get_current_user()
    recent_activity = get_db().execute(
        """
        SELECT url, status, requested_at
        FROM logs
        WHERE username = ?
        ORDER BY requested_at DESC
        LIMIT 6
        """,
        (session["user"],),
    ).fetchall()
    return render_template(
        "profile.html",
        username=session["user"],
        user=user,
        recent_activity=recent_activity,
        display_host=display_host,
        active_page="profile",
    )


@app.route("/settings")
def settings():
    if "user" not in session:
        return redirect(url_for("login"))

    preferences = {
        "session_security": "Enabled",
        "traffic_alerts": "Email alerts for blocked requests",
        "log_retention": "30 days",
        "role": "Administrator",
    }
    return render_template(
        "settings.html",
        username=session["user"],
        preferences=preferences,
        active_page="settings",
    )


@app.route("/traffic")
def traffic():
    if "user" not in session:
        return redirect(url_for("login"))
    ensure_proxy_server()
    summary, protocol_rows, top_destinations, traffic_feed, recent_alerts = get_traffic_data()
    return render_template(
        "traffic.html",
        username=session["user"],
        summary=summary,
        protocol_rows=protocol_rows,
        top_destinations=top_destinations,
        traffic_feed=traffic_feed,
        recent_alerts=recent_alerts,
        display_host=display_host,
        proxy_host=PROXY_HOST,
        proxy_port=PROXY_PORT,
        active_page="traffic",
    )


@app.route("/logs")
def logs():
    if "user" not in session:
        return redirect(url_for("login"))
    ensure_proxy_server()
    metrics, system_logs, blocked_activity, blocked_sites, activity_by_user = get_logs_data()
    return render_template(
        "logs.html",
        username=session["user"],
        metrics=metrics,
        system_logs=system_logs,
        blocked_activity=blocked_activity,
        blocked_sites=blocked_sites,
        activity_by_user=activity_by_user,
        display_host=display_host,
        active_page="logs",
    )


@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("You have been logged out.")
    return redirect(url_for("home"))


init_db()


if __name__ == "__main__":
    ensure_proxy_server()
    app.run(debug=True, use_reloader=False)
