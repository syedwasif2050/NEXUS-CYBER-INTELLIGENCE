
import sqlite3
import json


class DatabaseManager:

    def __init__(self, db_path="database/cyber_threats.db"):
        self.connection = sqlite3.connect(db_path)
        self.create_tables()

    def create_tables(self):

        cursor = self.connection.cursor()

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

        self.connection.commit()

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
                (username, source_ip, incident_type, severity, related_events)
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
        self.connection.close()
