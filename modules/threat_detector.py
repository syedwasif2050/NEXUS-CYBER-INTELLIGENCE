
from collections import defaultdict


class ThreatDetector:

    def __init__(self):
        self.alerts = []

    def detect_threats(self, events):

        self.alerts = []
        failed_logins = defaultdict(list)

        for event in events:

            username = event["username"]
            source_ip = event["source_ip"]
            event_type = event["event_type"]
            status = event["status"]

            # Rule 1: Track failed login attempts
            if event_type == "LOGIN" and status == "FAILED":
                failed_logins[username].append(event)

            # Rule 2: Access denied
            if event_type == "ACCESS" and status == "DENIED":

                self.alerts.append({
                    "username": username,
                    "source_ip": source_ip,
                    "threat": "Access Denied",
                    "severity": "LOW",
                    "details": "An access attempt was denied."
                })

            # Rule 3: Suspicious network activity
            if event_type == "NETWORK" and status == "SUSPICIOUS":

                self.alerts.append({
                    "username": username,
                    "source_ip": source_ip,
                    "threat": "Suspicious Network Activity",
                    "severity": "MEDIUM",
                    "details": "A suspicious network event was detected."
                })

        # Rule 4: Multiple failed login attempts
        for username, attempts in failed_logins.items():

            if len(attempts) >= 3:

                self.alerts.append({
                    "username": username,
                    "source_ip": attempts[0]["source_ip"],
                    "threat": "Multiple Failed Login Attempts",
                    "severity": "HIGH",
                    "details": f"{len(attempts)} failed login attempts detected."
                })

        return self.alerts
