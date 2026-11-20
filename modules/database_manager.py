import sqlite3
from pathlib import Path
from datetime import datetime, timezone

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB = BASE_DIR / "database" / "cyber_threats.db"


def current_timestamp():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


class DatabaseManager:

    def __init__(self, db_path=None):
        path = Path(db_path) if db_path else DEFAULT_DB

        if not path.is_absolute():
            path = BASE_DIR / path

        path.parent.mkdir(parents=True, exist_ok=True)

        self.connection = sqlite3.connect(
            str(path),
            timeout=30,
            check_same_thread=False
        )

        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys=ON")

        self.create_tables()

    def create_tables(self):
        self.connection.executescript("""
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            username TEXT,
            source_ip TEXT,
            event_type TEXT,
            status TEXT
        );

        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            source_ip TEXT,
            incident_type TEXT,
            severity TEXT,
            related_events INTEGER
        );

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE COLLATE NOCASE NOT NULL,
            email TEXT DEFAULT '',
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT UNIQUE NOT NULL,
            source_ip TEXT,
            device_info TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            revoked INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            username TEXT,
            source_ip TEXT,
            event_type TEXT,
            status TEXT,
            details TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            username TEXT,
            source_ip TEXT,
            threat TEXT,
            severity TEXT,
            details TEXT,
            status TEXT DEFAULT 'open'
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            actor TEXT,
            action TEXT,
            target TEXT,
            details TEXT
        );
        """)

        self.connection.commit()

    def _rows(self, sql, params=()):
        return [
            dict(row)
            for row in self.connection.execute(sql, params).fetchall()
        ]

    def save_logs(self, events):
        self.connection.executemany(
            """
            INSERT INTO security_logs
            (timestamp, username, source_ip, event_type, status)
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                (
                    str(event.get("timestamp") or current_timestamp()),
                    event.get("username", ""),
                    event.get("source_ip", ""),
                    event.get("event_type", ""),
                    event.get("status", "")
                )
                for event in events
            ]
        )
        self.connection.commit()

    def save_incidents(self, incidents):
        self.connection.executemany(
            """
            INSERT INTO incidents
            (username, source_ip, incident_type, severity, related_events)
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                (
                    incident.get("username", ""),
                    incident.get("source_ip", ""),
                    incident.get("incident_type", ""),
                    incident.get("severity", ""),
                    incident.get("related_events", 0)
                )
                for incident in incidents
            ]
        )
        self.connection.commit()

    def get_logs(self):
        return self._rows(
            "SELECT * FROM security_logs ORDER BY id DESC"
        )

    def get_incidents(self):
        return self._rows(
            "SELECT * FROM incidents ORDER BY id DESC"
        )

    def create_user(self, username, email, password_hash, role="user"):
        timestamp = current_timestamp()

        cursor = self.connection.execute(
            """
            INSERT INTO users
            (username, email, password_hash, role, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                username.strip(),
                email or "",
                password_hash,
                role,
                "active",
                timestamp
            )
        )

        self.connection.commit()
        return cursor.lastrowid

    def get_user(self, username):
        rows = self._rows(
            "SELECT * FROM users WHERE username=? COLLATE NOCASE",
            (username,)
        )
        return rows[0] if rows else None

    def get_session_user(self, token_hash):
        rows = self._rows(
            """
            SELECT u.id, u.username, u.email, u.role, u.status
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token_hash=? AND s.revoked=0
            """,
            (token_hash,)
        )
        return rows[0] if rows else None

    def add_session(self, user_id, token_hash, source_ip, device_info):
        self.connection.execute(
            """
            INSERT INTO sessions
            (user_id, token_hash, source_ip, device_info, created_at, revoked)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                token_hash,
                source_ip,
                device_info,
                current_timestamp(),
                0
            )
        )
        self.connection.commit()

    def revoke_token(self, token_hash):
        self.connection.execute(
            "UPDATE sessions SET revoked=1 WHERE token_hash=?",
            (token_hash,)
        )
        self.connection.commit()

    def revoke_user_sessions(self, user_id):
        self.connection.execute(
            "UPDATE sessions SET revoked=1 WHERE user_id=?",
            (user_id,)
        )
        self.connection.commit()

    def get_all_users(self):
        return self._rows(
            """
            SELECT id, username, email, role, status, created_at
            FROM users ORDER BY id DESC
            """
        )

    def update_user_status(self, username, status):
        self.connection.execute(
            "UPDATE users SET status=? WHERE username=? COLLATE NOCASE",
            (status, username)
        )
        self.connection.commit()

    def get_active_sessions(self):
        return self._rows(
            """
            SELECT s.id, u.username, u.role, s.source_ip,
                   s.device_info, s.created_at
            FROM sessions s
            JOIN users u ON u.id=s.user_id
            WHERE s.revoked=0 AND u.status='active'
            ORDER BY s.id DESC
            """
        )

    def add_security_event(
        self, username, source_ip, event_type, status, details=""
    ):
        timestamp = current_timestamp()

        self.connection.execute(
            """
            INSERT INTO security_events
            (timestamp, username, source_ip, event_type, status, details)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                timestamp,
                username,
                source_ip,
                event_type,
                status,
                details
            )
        )
        self.connection.commit()

        if event_type == "LOGIN" and status == "FAILED":
            result = self.connection.execute(
                """
                SELECT COUNT(*)
                FROM security_events
                WHERE username=?
                AND event_type='LOGIN'
                AND status='FAILED'
                AND timestamp >= datetime('now', '-15 minutes')
                """,
                (username,)
            ).fetchone()

            count = result[0]

            if count == 3:
                self.connection.execute(
                    """
                    INSERT INTO alerts
                    (timestamp, username, source_ip, threat,
                     severity, details, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        current_timestamp(),
                        username,
                        source_ip,
                        "Repeated Failed Login Attempts",
                        "HIGH",
                        f"{count} failed attempts in 15 minutes",
                        "open"
                    )
                )
                self.connection.commit()

    def get_security_events(self, limit=500):
        return self._rows(
            "SELECT * FROM security_events ORDER BY id DESC LIMIT ?",
            (int(limit),)
        )

    def get_alerts(self, limit=500):
        return self._rows(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ?",
            (int(limit),)
        )

    def update_alert_status(self, alert_id, status):
        self.connection.execute(
            "UPDATE alerts SET status=? WHERE id=?",
            (status, alert_id)
        )
        self.connection.commit()

    def add_audit_log(self, actor, action, target, details):
        self.connection.execute(
            """
            INSERT INTO audit_logs
            (timestamp, actor, action, target, details)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                current_timestamp(),
                actor,
                action,
                target,
                details
            )
        )
        self.connection.commit()

    def get_audit_logs(self, limit=500):
        return self._rows(
            "SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?",
            (int(limit),)
        )

    def close(self):
        self.connection.close()