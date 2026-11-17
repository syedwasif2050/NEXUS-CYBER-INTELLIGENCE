
from collections import defaultdict


class IncidentCorrelator:

    def __init__(self):
        self.incidents = []

    def correlate_events(self, events):

        self.incidents = []

        # Group events by username and source IP
        grouped_events = defaultdict(list)

        for event in events:

            key = (
                event["username"],
                event["source_ip"]
            )

            grouped_events[key].append(event)

        # Analyze each group
        for (username, source_ip), user_events in grouped_events.items():

            failed_count = sum(
                1 for event in user_events
                if event["event_type"] == "LOGIN"
                and event["status"] == "FAILED"
            )

            successful_count = sum(
                1 for event in user_events
                if event["event_type"] == "LOGIN"
                and event["status"] == "SUCCESS"
            )

            denied_count = sum(
                1 for event in user_events
                if event["event_type"] == "ACCESS"
                and event["status"] == "DENIED"
            )

            suspicious_count = sum(
                1 for event in user_events
                if event["event_type"] == "NETWORK"
                and event["status"] == "SUSPICIOUS"
            )

            # Identify related incident patterns
            if failed_count >= 3 and successful_count >= 1:

                incident_type = "Repeated Failed Logins Followed by Success"
                severity = "HIGH"

            elif failed_count >= 3:

                incident_type = "Repeated Failed Login Attempts"
                severity = "HIGH"

            elif suspicious_count >= 1:

                incident_type = "Suspicious Network Incident"
                severity = "MEDIUM"

            elif denied_count >= 1:

                incident_type = "Access Denied Incident"
                severity = "LOW"

            else:
                continue

            incident = {
                "username": username,
                "source_ip": source_ip,
                "incident_type": incident_type,
                "severity": severity,
                "related_events": len(user_events),
                "failed_logins": failed_count,
                "successful_logins": successful_count,
                "access_denied": denied_count,
                "suspicious_network": suspicious_count
            }

            self.incidents.append(incident)

        return self.incidents
