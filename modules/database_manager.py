
import sqlite3
from pathlib import Path
from datetime import datetime, timezone


class DatabaseManager:
    def __init__(self, db_path="database/cyber_threats.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.connection = sqlite3.connect(
            str(self.db_path),
            check_same_thread=False,
            timeout=15
        )
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA journal_mode = WAL")

        self.create_tables()

    @staticmethod
    def now():
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def create_tables(self):
        cursor = self.connection.cursor()

        # Existing tables: retained for compatibility
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                username TEXT,
                source_ip TEXT,
                event_type TEXT,
                status TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                source_ip TEXT,
                incident_type TEXT,
                severity TEXT,
                related_events INTEGER
            )
        """)

        # Registered NEXUS users
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                email TEXT UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user'
                    CHECK(role IN ('admin', 'user')),
                status TEXT NOT NULL DEFAULT 'active'
                    CHECK(status IN ('active', 'blocked', 'locked')),
                created_at TEXT NOT NULL,
                last_login TEXT
            )
        """)

        # Login sessions. Store only a hash of the session token.
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS auth_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                device_info TEXT,
                source_ip TEXT,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)

        # Authentication and security activity
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                username TEXT,
                source_ip TEXT,
                event_type TEXT NOT NULL,
                status TEXT NOT NULL,
                details TEXT,
                severity TEXT DEFAULT 'INFO'
            )
        """)

        # Admin actions and important account changes
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                actor_username TEXT,
                action TEXT NOT NULL,
                target_username TEXT,
                details TEXT
            )
        """)

        # Detected threats and alerts
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                username TEXT,
                source_ip TEXT,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                status TEXT NOT NULL DEFAULT 'open'
            )
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_username
            ON security_events(username)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_timestamp
            ON security_events(timestamp)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_sessions_user
            ON auth_sessions(user_id)
        """)

        self.connection.commit()

    # ---------------- USER MANAGEMENT ----------------

    def create_user(self, username, email, password_hash, role="user"):
        username = username.strip()
        email = email.strip().lower() if email else None

        if not username or not password_hash:
            raise ValueError("Username and password hash are required.")

        if role not in ("admin", "user"):
            raise ValueError("Invalid user role.")

        try:
            cursor = self.connection.execute("""
                INSERT INTO users
                (username, email, password_hash, role, status, created_at)
                VALUES (?, ?, ?, ?, 'active', ?)
            """, (username, email, password_hash, role, self.now()))

            self.connection.commit()
            return cursor.lastrowid

        except sqlite3.IntegrityError as error:
            self.connection.rollback()
            raise ValueError("Username or email already exists.") from error

    def get_user(self, username):
        row = self.connection.execute("""
            SELECT * FROM users
            WHERE username = ? COLLATE NOCASE
        """, (username.strip(),)).fetchone()

        return dict(row) if row else None

    def get_user_by_id(self, user_id):
        row = self.connection.execute("""
            SELECT * FROM users WHERE id = ?
        """, (user_id,)).fetchone()

        return dict(row) if row else None

    def get_all_users(self):
        rows = self.connection.execute("""
            SELECT id, username, email, role, status, created_at, last_login
            FROM users
            ORDER BY created_at DESC
        """).fetchall()

        return [dict(row) for row in rows]

    def update_user_status(self, username, status):
        if status not in ("active", "blocked", "locked"):
            raise ValueError("Invalid account status.")

        cursor = self.connection.execute("""
            UPDATE users SET status = ?
            WHERE username = ? COLLATE NOCASE
        """, (status, username.strip()))

        self.connection.commit()
        return cursor.rowcount > 0

    def update_last_login(self, user_id):
        self.connection.execute("""
            UPDATE users SET last_login = ? WHERE id = ?
        """, (self.now(), user_id))
        self.connection.commit()

    # ---------------- SESSION MANAGEMENT ----------------

    def create_session(
        self, user_id, token_hash, device_info,
        source_ip, expires_at
    ):
        cursor = self.connection.execute("""
            INSERT INTO auth_sessions
            (user_id, token_hash, device_info, source_ip,
             created_at, expires_at, revoked)
            VALUES (?, ?, ?, ?, ?, ?, 0)
        """, (
            user_id, token_hash, device_info,
            source_ip, self.now(), expires_at
        ))

        self.connection.commit()
        return cursor.lastrowid

    def get_session(self, token_hash):
        row = self.connection.execute("""
            SELECT s.*, u.username, u.role, u.status
            FROM auth_sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = ?
        """, (token_hash,)).fetchone()

        return dict(row) if row else None

    def revoke_session(self, session_id):
        self.connection.execute("""
            UPDATE auth_sessions SET revoked = 1
            WHERE id = ?
        """, (session_id,))
        self.connection.commit()

    def revoke_user_sessions(self, user_id):
        self.connection.execute("""
            UPDATE auth_sessions SET revoked = 1
            WHERE user_id = ? AND revoked = 0
        """, (user_id,))
        self.connection.commit()

    def get_active_sessions(self):
        rows = self.connection.execute("""
            SELECT s.id, u.username, s.device_info,
                   s.source_ip, s.created_at, s.expires_at
            FROM auth_sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.revoked = 0
              AND s.expires_at > ?
              AND u.status = 'active'
            ORDER BY s.created_at DESC
        """, (self.now(),)).fetchall()

        return [dict(row) for row in rows]

    # ---------------- SECURITY EVENTS ----------------

    def add_security_event(
        self, username, source_ip, event_type,
        status, details="", severity="INFO"
    ):
        cursor = self.connection.execute("""
            INSERT INTO security_events
            (timestamp, username, source_ip, event_type,
             status, details, severity)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            self.now(), username, source_ip,
            event_type, status, details, severity
        ))

        self.connection.commit()
        return cursor.lastrowid

    def get_security_events(self, limit=500):
        rows = self.connection.execute("""
            SELECT * FROM security_events
            ORDER BY id DESC LIMIT ?
        """, (limit,)).fetchall()

        return [dict(row) for row in rows]

    # ---------------- AUDIT LOGS ----------------

    def add_audit_log(
        self, actor_username, action,
        target_username=None, details=""
    ):
        self.connection.execute("""
            INSERT INTO audit_logs
            (timestamp, actor_username, action,
             target_username, details)
            VALUES (?, ?, ?, ?, ?)
        """, (
            self.now(), actor_username,
            action, target_username, details
        ))

        self.connection.commit()

    def get_audit_logs(self, limit=500):
        rows = self.connection.execute("""
            SELECT * FROM audit_logs
            ORDER BY id DESC LIMIT ?
        """, (limit,)).fetchall()

        return [dict(row) for row in rows]

    # ---------------- ALERTS ----------------

    def add_alert(
        self, username, source_ip, alert_type,
        severity, description
    ):
        cursor = self.connection.execute("""
            INSERT INTO alerts
            (timestamp, username, source_ip, alert_type,
             severity, description, status)
            VALUES (?, ?, ?, ?, ?, ?, 'open')
        """, (
            self.now(), username, source_ip,
            alert_type, severity, description
        ))

        self.connection.commit()
        return cursor.lastrowid

    def get_alerts(self, status=None, limit=500):
        if status:
            rows = self.connection.execute("""
                SELECT * FROM alerts
                WHERE status = ?
                ORDER BY id DESC LIMIT ?
            """, (status, limit)).fetchall()
        else:
            rows = self.connection.execute("""
                SELECT * FROM alerts
                ORDER BY id DESC LIMIT ?
            """, (limit,)).fetchall()

        return [dict(row) for row in rows]

    def update_alert_status(self, alert_id, status):
        if status not in ("open", "investigating", "resolved"):
            raise ValueError("Invalid alert status.")

        self.connection.execute("""
            UPDATE alerts SET status = ? WHERE id = ?
        """, (status, alert_id))
        self.connection.commit()

    # ---------------- EXISTING PROJECT METHODS ----------------

    def save_logs(self, events):
        cursor = self.connection.cursor()

        for event in events:
            cursor.execute("""
                INSERT INTO security_logs
                (timestamp, username, source_ip, event_type, status)
                VALUES (?, ?, ?, ?, ?)
            """, (
                str(event["timestamp"]),
                event["username"],
                event["source_ip"],
                event["event_type"],
                event["status"]
            ))

        self.connection.commit()

    def save_incidents(self, incidents):
        cursor = self.connection.cursor()

        for incident in incidents:
            cursor.execute("""
                INSERT INTO incidents
                (username, source_ip, incident_type,
                 severity, related_events)
                VALUES (?, ?, ?, ?, ?)
            """, (
                incident["username"],
                incident["source_ip"],
                incident["incident_type"],
                incident["severity"],
                incident["related_events"]
            ))

        self.connection.commit()

    def get_logs(self):
        return self.connection.execute(
            "SELECT * FROM security_logs"
        ).fetchall()

    def get_incidents(self):
        return self.connection.execute(
            "SELECT * FROM incidents"
        ).fetchall()

    def close(self):
        if self.connection:
            self.connection.close()
