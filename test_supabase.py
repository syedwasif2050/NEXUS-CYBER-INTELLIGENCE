
from modules.authentication import AuthenticationService
import streamlit as st

service = AuthenticationService()

try:
    cfg = st.secrets["admin"]
    username = cfg["username"]
    password = cfg["password"]

    user = service.db.get_user(username)

    print("Admin found:", bool(user))

    if user:
        print("Username matches:", user["username"] == username)
        print("Role:", user["role"])
        print("Status:", user["status"])

        verified = service.verify_password(
            password,
            user["password_hash"]
        )
        print("Password verified:", verified)

    result = service.login(
        username,
        password,
        "Local Test",
        "Test Browser"
    )

    print("Login result:", result.get("success"))
    print("Login message:", result.get("message", "Login successful"))

finally:
    service.close()
