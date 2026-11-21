
import streamlit as st
import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool
from datetime import datetime, timezone


def current_timestamp():
    return datetime.now(timezone.utc)


@st.cache_resource
def get_connection_pool(database_url):
    pool = ConnectionPool(
        conninfo=database_url,
        min_size=1,
        max_size=5,
        timeout=15,
        kwargs={
            "row_factory": dict_row,
            "connect_timeout": 15
        },
        open=False
    )

    pool.open(wait=True)
    return pool


class DatabaseManager:

    def __init__(self, db_path=None):
        database_url = st.secrets.get("DATABASE_URL")

        if not database_url:
            raise RuntimeError(
                "DATABASE_URL missing from Streamlit secrets."
            )

        self.pool = get_connection_pool(database_url)
        self.connection = self.pool.getconn()
        self._closed = False

    # DATABASE CHECK

    def create_tables(self):
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        self.connection.commit()

    # COMMON DATABASE HELPER

    def _rows(self, sql, params=()):
        with self.connection.cursor() as cursor:
            cursor.execute(sql, params)
            return cursor.fetchall()

    # SECURITY LOGS

    def save_logs(self, events):
        with self.connection.cursor() as cursor:
            for event in events:
                cursor.execute(
                    """
                    INSERT INTO security_logs
                    (timestamp, username, source_ip, event_type, status)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (
                        event.get("timestamp") or current_timestamp(),
                        event.get("username", ""),
                        event.get("source_ip", ""),
                        event.get("event_type", ""),
                        event.get("status", "")
                    )
                )
        self.connection.commit()

    def get_logs(self):
        return self._rows(
            "SELECT * FROM security_logs ORDER BY id DESC"
        )

    # INCIDENTS

    def save_incidents(self, incidents):
        with self.connection.cursor() as cursor:
            for incident in incidents:
                cursor.execute(
                    """
                    INSERT INTO incidents
                    (username, source_ip, incident_type, severity, related_events)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (
                        incident.get("username", ""),
                        incident.get("source_ip", ""),
                        incident.get("incident_type", ""),
                        incident.get("severity", ""),
                        incident.get("related_events", 0)
                    )
                )
        self.connection.commit()

    def get_incidents(self):
        return self._rows(
            "SELECT * FROM incidents ORDER BY id DESC"
        )

    # USERS

    def create_user(self, username, email, password_hash, role="user"):
        with self.connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO users
                (username, email, password_hash, role, status, created_at)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    username.strip(),
                    email or "",
                    password_hash,
                    role,
                    "active",
                    current_timestamp()
                )
            )
            result = cursor.fetchone()

        self.connection.commit()
        return result["id"]

    def get_user(self, username):
        rows = self._rows(
            """
            SELECT *
            FROM users
            WHERE LOWER(username) = LOWER(%s)
            LIMIT 1
            """,
            (username,)
        )
        return rows[0] if rows else None

    def get_all_users(self):
        return self._rows(
            """
            SELECT id, username, email, role, status, created_at
            FROM users
            ORDER BY id DESC
            """
        )

    def update_user_status(self, username, status):
        with self.connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE users
                SET status = %s
                WHERE LOWER(username) = LOWER(%s)
                """,
                (status, username)
            )
        self.connection.commit()

    def update_user_password(self, username, password_hash):
        with self.connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE users
                SET password_hash = %s
                WHERE LOWER(username) = LOWER(%s)
                """,
                (password_hash, username)
            )
        self.connection.commit()

    # SESSIONS

    def get_session_user(self, token_hash):
        rows = self._rows(
            """
            SELECT
                u.id,
                u.username,
                u.email,
                u.role,
                u.status
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = %s
              AND s.revoked = FALSE
              AND u.status = 'active'
            LIMIT 1
            """,
            (token_hash,)
        )
        return rows[0] if rows else None

    def get_session_details(self, token_hash):
        rows = self._rows(
            """
            SELECT u.username, s.source_ip
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = %s
            LIMIT 1
            """,
            (token_hash,)
        )
        return rows[0] if rows else None

    def add_session(self, user_id, token_hash, source_ip, device_info):
        with self.connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO sessions
                (user_id, token_hash, source_ip, device_info, created_at, revoked)
                VALUES (%s, %s, %s, %s, %s, FALSE)
                """,
                (
                    user_id,
                    token_hash,
                    source_ip,
                    device_info,
                    current_timestamp()
                )
            )
        self.connection.commit()

    def revoke_token(self, token_hash):
        with self.connection.cursor() as cursor:
            cursor.execute(
                "UPDATE sessions SET revoked = TRUE WHERE token_hash = %s",
                (token_hash,)
            )
        self.connection.commit()

    def revoke_user_sessions(self, user_id):
        with self.connection.cursor() as cursor:
            cursor.execute(
                "UPDATE sessions SET revoked = TRUE WHERE user_id = %s",
                (user_id,)
            )
        self.connection.commit()

    def get_active_sessions(self):
        return self._rows(
            """
            SELECT
                s.id,
                u.username,
                u.role,
                s.source_ip,
                s.device_info,
                s.created_at
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.revoked = FALSE
              AND u.status = 'active'
            ORDER BY s.id DESC
            """
        )

    # SECURITY EVENTS

    def add_security_event(
        self,
        username,
        source_ip,
        event_type,
        status,
        details=""
    ):
        with self.connection.cursor() as cursor:

            # Save the actual security event
            cursor.execute(
                """
                INSERT INTO security_events
                (timestamp, username, source_ip, event_type, status, details)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    current_timestamp(),
                    username,
                    source_ip,
                    event_type,
                    status,
                    details
                )
            )

            # Detect repeated failed logins
            if event_type == "LOGIN" and status == "FAILED":

                cursor.execute(
                    """
                    SELECT COUNT(*) AS total
                    FROM security_events
                    WHERE username = %s
                      AND source_ip IS NOT DISTINCT FROM %s
                      AND event_type = 'LOGIN'
                      AND status = 'FAILED'
                      AND timestamp >= NOW() - INTERVAL '15 minutes'
                    """,
                    (username, source_ip)
                )

                count = cursor.fetchone()["total"]

                # Threshold: 3 or more failures in 15 minutes
                if count >= 3:

                    # Check for an existing open alert
                    cursor.execute(
                        """
                        SELECT id
                        FROM alerts
                        WHERE username = %s
                          AND source_ip IS NOT DISTINCT FROM %s
                          AND threat = 'Repeated Failed Login Attempts'
                          AND status = 'open'
                        LIMIT 1
                        """,
                        (username, source_ip)
                    )

                    existing = cursor.fetchone()

                    # Create one alert and one incident
                    # when no open alert already exists
                    if not existing:

                        cursor.execute(
                            """
                            INSERT INTO alerts
                            (timestamp, username, source_ip, threat,
                             severity, details, status)
                            VALUES (%s, %s, %s, %s, %s, %s, %s)
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

                        cursor.execute(
                            """
                            INSERT INTO incidents
                            (username, source_ip, incident_type,
                             severity, related_events)
                            VALUES (%s, %s, %s, %s, %s)
                            """,
                            (
                                username,
                                source_ip,
                                "Repeated Failed Login Attempts",
                                "HIGH",
                                count
                            )
                        )

        self.connection.commit()

    def get_security_events(self, limit=500):
        return self._rows(
            """
            SELECT *
            FROM security_events
            ORDER BY id DESC
            LIMIT %s
            """,
            (int(limit),)
        )

    # ALERTS

    def get_alerts(self, limit=500):
        return self._rows(
            """
            SELECT *
            FROM alerts
            ORDER BY id DESC
            LIMIT %s
            """,
            (int(limit),)
        )

    def update_alert_status(self, alert_id, status):
        with self.connection.cursor() as cursor:
            cursor.execute(
                "UPDATE alerts SET status = %s WHERE id = %s",
                (status, alert_id)
            )
        self.connection.commit()

    # AUDIT LOGS

    def add_audit_log(self, actor, action, target, details):
        with self.connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO audit_logs
                (timestamp, actor_username, action, target_username, details)
                VALUES (%s, %s, %s, %s, %s)
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
            """
            SELECT *
            FROM audit_logs
            ORDER BY id DESC
            LIMIT %s
            """,
            (int(limit),)
        )

    # CLOSE CONNECTION - RETURN TO POOL

    def close(self):
        if not self._closed and self.connection is not None:
            try:
                self.connection.rollback()
            finally:
                self.pool.putconn(self.connection)
                self.connection = None
                self._closed = True
