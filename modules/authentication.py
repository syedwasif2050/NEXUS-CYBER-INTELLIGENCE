import hashlib
import hmac
import secrets
import re

from modules.database_manager import DatabaseManager


class AuthenticationService:

    ITERATIONS = 240000

    def __init__(self, db_path=None):
        self.db = DatabaseManager(db_path)

    @classmethod
    def hash_password(cls, password):
        salt = secrets.token_bytes(16)

        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            salt,
            cls.ITERATIONS
        )

        return (
            f"pbkdf2_sha256${cls.ITERATIONS}"
            f"${salt.hex()}${digest.hex()}"
        )

    @staticmethod
    def verify_password(password, stored):
        try:
            algo, iterations, salt, digest = stored.split("$")

            if algo != "pbkdf2_sha256":
                return False

            check = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode(),
                bytes.fromhex(salt),
                int(iterations)
            ).hex()

            return hmac.compare_digest(check, digest)

        except Exception:
            return False

    def register_user(self, username, email, password):
        username = (username or "").strip()

        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,30}", username):
            raise ValueError(
                "Username must be 3-30 characters: "
                "letters, numbers, dot, underscore or hyphen."
            )

        if len(password or "") < 8:
            raise ValueError(
                "Password must contain at least 8 characters."
            )

        if self.db.get_user(username):
            raise ValueError("Username already exists.")

        self.db.create_user(
            username,
            email,
            self.hash_password(password),
            "user"
        )

        self.db.add_security_event(
            username,
            "Registration",
            "REGISTER",
            "SUCCESS",
            "Account created"
        )

        self.db.add_audit_log(
            username,
            "REGISTER",
            "ACCOUNT",
            "User self-registration"
        )

    def create_admin(self, username, password):
        username = (username or "").strip()

        if len(password or "") < 12:
            raise ValueError(
                "Admin password must be at least 12 characters."
            )

        existing = self.db.get_user(username)

        if existing:
            if existing["role"] != "admin":
                raise ValueError(
                    "This username already belongs to a normal user. "
                    "Choose another admin username."
                )

            self.db.connection.execute(
                """
                UPDATE users
                SET password_hash=?, status='active'
                WHERE username=? COLLATE NOCASE
                """,
                (self.hash_password(password), username)
            )

            self.db.connection.commit()
            return False

        self.db.create_user(
            username,
            "",
            self.hash_password(password),
            "admin"
        )

        self.db.add_audit_log(
            "SYSTEM",
            "ADMIN_BOOTSTRAP",
            username,
            "Admin provisioned from Streamlit secrets"
        )

        return True

    def login(
        self,
        username,
        password,
        source_ip="Unknown",
        device_info="Browser"
    ):
        username = (username or "").strip()
        user = self.db.get_user(username)

        if not user or not self.verify_password(
            password or "",
            user["password_hash"]
        ):
            self.db.add_security_event(
                username or "unknown",
                source_ip,
                "LOGIN",
                "FAILED",
                "Invalid credentials"
            )

            return {
                "success": False,
                "message": "Invalid username or password."
            }

        if user["status"] != "active":
            self.db.add_security_event(
                user["username"],
                source_ip,
                "LOGIN",
                "DENIED",
                "Account blocked or locked"
            )

            return {
                "success": False,
                "message": (
                    "Account is blocked or locked. "
                    "Contact administrator."
                )
            }

        token = secrets.token_urlsafe(36)
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        self.db.add_session(
            user["id"],
            token_hash,
            source_ip,
            device_info
        )

        self.db.add_security_event(
            user["username"],
            source_ip,
            "LOGIN",
            "SUCCESS",
            "Login successful"
        )

        return {
            "success": True,
            "token": token
        }

    def verify_session(self, token):
        if not token:
            return None

        digest = hashlib.sha256(token.encode()).hexdigest()
        user = self.db.get_session_user(digest)

        if not user or user["status"] != "active":
            return None

        return {
            key: user[key]
            for key in ("id", "username", "email", "role", "status")
        }

    def logout(self, token):
        if token:
            digest = hashlib.sha256(token.encode()).hexdigest()
            self.db.revoke_token(digest)

    def close(self):
        self.db.close()