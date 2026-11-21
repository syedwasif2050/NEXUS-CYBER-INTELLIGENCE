
import time
import streamlit as st
from modules.database_manager import DatabaseManager
from modules.authentication import AuthenticationService

print("\n===== NEXUS PERFORMANCE TEST =====")

# Test 1: Database connection
start = time.perf_counter()
db = DatabaseManager()
print("Database connection:", round(time.perf_counter() - start, 3), "seconds")

# Test 2: User lookup
start = time.perf_counter()
user = db.get_user("admin")
print("Admin lookup:", round(time.perf_counter() - start, 3), "seconds")

db.close()

# Test 3: Session verification
service = AuthenticationService()

try:
    start = time.perf_counter()
    service.db.get_all_users()
    print("User query:", round(time.perf_counter() - start, 3), "seconds")
finally:
    service.close()

print("===== TEST COMPLETED =====")
