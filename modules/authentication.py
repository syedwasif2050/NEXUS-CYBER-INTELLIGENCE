
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from modules.database_manager import DatabaseManager


PBKDF2_ITERATIONS = 600_000
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 10
SESSION_HOURS = 8


def now_utc():
    return datetime.now(timezone.utc)


def hash_password(password):
    if len(password) < 10:
        raise ValueError("Password must contain at least 10 characters.")

    salt = secrets.token_bytes(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS
    )

    return (
        f"pbkdf2_sha256${PBKDF2_ITERATIONS}"
        f"${salt.hex()}${password_hash.hex()}"
    )


def verify_password(password, stored_hash):
    try:
        algorithm, iterations, salt_hex, hash_hex = stored_hash.split("$")

        if algorithm != "pbkdf2_sha256":
            return False

        calculated = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            int(iterations)
        )

        return hmac.compare_digest(calculated.hex(), hash_hex)

    except (ValueError, TypeError):
        return False


class AuthenticationService:
    def __init__(self, db=None):
        self.db = db or DatabaseManager()

    def register_user(self, username, email, password):
        username = username.strip()

        if len(username) < 3:
            raise ValueError("Username must contain at least 3 characters.")

        if not username.replace("_", "").isalnum():
            raise ValueError("Use only letters, numbers and underscores.")

        password_hash = hash_password(password)

        user_id = self.db.create_user(
            username=username,
            email=email,
            password_hash=password_hash,
            role="user"
        )

        self.db.add_security_event(
            username, None, "REGISTER", "SUCCESS",
            "New user account registered.", "INFO"
        )

        self.db.add_audit_log(
            username, "USER_REGISTERED", username,
            "New user registration."
        )

        return user_id

    def _failed_attempts(self, username):
        cutoff = (
            now_utc() - timedelta(minutes=LOCKOUT_MINUTES)
        ).isoformat(timespec="seconds")

        row = self.db.connection.execute("""
            SELECT COUNT(*) AS total
            FROM security_events
            WHERE username = ? COLLATE NOCASE
              AND event_type = 'LOGIN'
              AND status = 'FAILED'
              AND timestamp >= ?
        """, (username, cutoff)).fetchone()

        return row["total"]

    def login(self, username, password, source_ip="Unknown",
              device_info="Unknown device"):

        username = username.strip()
        user = self.db.get_user(username)

        if user and user["status"] != "active":
            self.db.add_security_event(
                username, source_ip, "LOGIN", "DENIED",
                "Account is not active.", "HIGH"
            )
            return {"success": False, "message": "Account is blocked or locked."}

        if self._failed_attempts(username) >= MAX_FAILED_ATTEMPTS:
            if user:
                self.db.update_user_status(username, "locked")

            self.db.add_security_event(
                username, source_ip, "LOGIN", "DENIED",
                "Too many recent failed login attempts.", "HIGH"
            )

            self.db.add_alert(
                username, source_ip, "ACCOUNT_LOCKOUT", "HIGH",
                "Repeated failed login attempts detected."
            )

            return {
                "success": False,
                "message": "Too many failed attempts. Contact the administrator."
            }

        if not user or not verify_password(password, user["password_hash"]):
            self.db.add_security_event(
                username, source_ip, "LOGIN", "FAILED",
                "Invalid username or password.", "MEDIUM"
            )

            if self._failed_attempts(username) >= MAX_FAILED_ATTEMPTS:
                if user:
                    self.db.update_user_status(username, "locked")

                self.db.add_alert(
                    username, source_ip, "REPEATED_LOGIN_FAILURES", "HIGH",
                    "Five or more failed login attempts within ten minutes."
                )

            return {"success": False, "message": "Invalid username or password."}

        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        created = now_utc()
        expires = created + timedelta(hours=SESSION_HOURS)

        session_id = self.db.create_session(
            user_id=user["id"],
            token_hash=token_hash,
            device_info=device_info,
            source_ip=source_ip,
            expires_at=expires.isoformat(timespec="seconds")
        )

        self.db.update_last_login(user["id"])

        self.db.add_security_event(
            username, source_ip, "LOGIN", "SUCCESS",
            "User login successful.", "INFO"
        )

        self.db.add_audit_log(
            username, "USER_LOGIN", username,
            "Successful login."
        )

        return {
            "success": True,
            "message": "Login successful.",
            "token": token,
            "session_id": session_id,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "role": user["role"]
            }
        }

    def verify_session(self, token):
        if not token:
            return None

        token_hash = hashlib.sha256(token.encode()).hexdigest()
        session = self.db.get_session(token_hash)

        if not session:
            return None

        if session["revoked"] or session["status"] != "active":
            return None

        try:
            expires = datetime.fromisoformat(session["expires_at"])
            if expires <= now_utc():
                return None
        except ValueError:
            return None

        return {
            "id": session["user_id"],
            "username": session["username"],
            "role": session["role"],
            "session_id": session["id"]
        }

    def logout(self, token):
        if not token:
            return False

        token_hash = hashlib.sha256(token.encode()).hexdigest()
        session = self.db.get_session(token_hash)

        if not session:
            return False

        self.db.revoke_session(session["id"])

        self.db.add_security_event(
            session["username"], session["source_ip"],
            "LOGOUT", "SUCCESS", "User logged out.", "INFO"
        )

        self.db.add_audit_log(
            session["username"], "USER_LOGOUT",
            session["username"], "User logged out."
        )

        return True

    def close(self):
        self.db.close()
