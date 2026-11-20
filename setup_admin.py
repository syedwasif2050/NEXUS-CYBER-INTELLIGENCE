
from getpass import getpass

from modules.database_manager import DatabaseManager
from modules.authentication import hash_password


def main():
    db = DatabaseManager()

    try:
        existing = db.connection.execute(
            "SELECT COUNT(*) FROM users WHERE role = 'admin'"
        ).fetchone()[0]

        if existing:
            print("An admin account already exists.")
            return

        print("\n===== NEXUS ADMIN SETUP =====")

        username = input("Admin username: ").strip()
        email = input("Admin email (optional): ").strip() or None

        password = getpass("Create admin password (minimum 10 characters): ")
        confirm = getpass("Confirm admin password: ")

        if password != confirm:
            print("Passwords do not match.")
            return

        password_hash = hash_password(password)

        user_id = db.create_user(
            username=username,
            email=email,
            password_hash=password_hash,
            role="admin"
        )

        db.add_audit_log(
            username,
            "ADMIN_CREATED",
            username,
            "Initial administrator account created."
        )

        print("\nADMIN ACCOUNT CREATED SUCCESSFULLY!")
        print("Admin ID:", user_id)
        print("Username:", username)
        print("Keep your password private.")

    except ValueError as error:
        print("Setup error:", error)

    finally:
        db.close()


if __name__ == "__main__":
    main()
