
from getpass import getpass
from modules.authentication import AuthenticationService


auth = AuthenticationService()

try:
    username = input("Username: ").strip()
    password = getpass("Password: ")

    result = auth.login(
        username,
        password,
        source_ip="127.0.0.1",
        device_info="NEXUS Local Test"
    )

    print("\nLogin result:", result["message"])

    if result["success"]:
        token = result["token"]

        print("Username:", result["user"]["username"])
        print("Role:", result["user"]["role"])

        verified = auth.verify_session(token)
        print("Session verified:", verified is not None)

        auth.logout(token)
        print("Logout successful.")

        verified_after_logout = auth.verify_session(token)
        print("Session active after logout:", verified_after_logout is not None)

finally:
    auth.close()
