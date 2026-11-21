from collections import defaultdict
from datetime import datetime, timedelta, timezone


class ThreatDetectionEngine:
    """
    NEXUS defensive event-analysis engine.
    Analyzes recorded security events and produces explainable findings.
    """

    FAILED_LOGIN_THRESHOLD = 5
    MULTI_ACCOUNT_THRESHOLD = 4
    PRIVILEGE_KEYWORDS = (
        "ADMIN",
        "PRIVILEGE",
        "ROLE_CHANGE",
        "PERMISSION",
    )

    @staticmethod
    def _value(event, *keys, default=None):
        for key in keys:
            value = event.get(key)
            if value is not None:
                return value
        return default

    @staticmethod
    def _normalize(event):
        return {
            **event,
            "event_type": str(
                event.get("event_type", event.get("type", "UNKNOWN"))
            ).upper(),
            "username": str(
                event.get("username", event.get("user", "unknown"))
            ),
            "source_ip": str(
                event.get("source_ip", event.get("ip_address", "unknown"))
            ),
        }

    @staticmethod
    def _time(event):
        value = event.get("timestamp", event.get("created_at"))

        if isinstance(value, datetime):
            return value

        if isinstance(value, str):
            try:
                value = value.replace("Z", "+00:00")
                return datetime.fromisoformat(value)
            except ValueError:
                return None

        return None

    def analyze(self, events):
        normalized = [self._normalize(e) for e in events]
        findings = []

        findings.extend(self.detect_repeated_failures(normalized))
        findings.extend(self.detect_multi_account_activity(normalized))
        findings.extend(self.detect_privilege_activity(normalized))
        findings.extend(self.detect_session_activity(normalized))

        return self.correlate(findings)

    # --------------------------------------------------
    # 1. Repeated failed login detection
    # --------------------------------------------------

    def detect_repeated_failures(self, events):
        groups = defaultdict(list)

        for event in events:
            event_type = event["event_type"]

            if "FAILED" not in event_type:
                continue

            groups[
                (event["username"], event["source_ip"])
            ].append(event)

        findings = []

        for (username, source_ip), group in groups.items():
            if len(group) < self.FAILED_LOGIN_THRESHOLD:
                continue

            findings.append({
                "rule": "Repeated Failed Login Attempts",
                "severity": "HIGH",
                "risk_score": 85,
                "username": username,
                "source_ip": source_ip,
                "event_count": len(group),
                "description": (
                    f"{len(group)} failed login events recorded "
                    f"for account {username}."
                ),
                "recommendation": (
                    "Review the account activity and verify "
                    "whether the login attempts are legitimate."
                ),
                "related_events": group,
            })

        return findings

    # --------------------------------------------------
    # 2. Multi-account activity detection
    # --------------------------------------------------

    def detect_multi_account_activity(self, events):
        groups = defaultdict(list)

        for event in events:
            if "FAILED" in event["event_type"]:
                groups[event["source_ip"]].append(event)

        findings = []

        for source_ip, group in groups.items():
            usernames = {
                event["username"]
                for event in group
                if event["username"] != "unknown"
            }

            if len(usernames) < self.MULTI_ACCOUNT_THRESHOLD:
                continue

            findings.append({
                "rule": "Multiple Accounts From Same Source",
                "severity": "HIGH",
                "risk_score": 90,
                "username": ", ".join(sorted(usernames)),
                "source_ip": source_ip,
                "event_count": len(group),
                "description": (
                    f"Failed login activity involving "
                    f"{len(usernames)} accounts from one source."
                ),
                "recommendation": (
                    "Investigate the source and review the "
                    "affected accounts."
                ),
                "related_events": group,
            })

        return findings

    # --------------------------------------------------
    # 3. Privilege activity monitoring
    # --------------------------------------------------

    def detect_privilege_activity(self, events):
        findings = []

        for event in events:
            event_type = event["event_type"]

            if not any(
                keyword in event_type
                for keyword in self.PRIVILEGE_KEYWORDS
            ):
                continue

            findings.append({
                "rule": "Privilege Related Activity",
                "severity": "MEDIUM",
                "risk_score": 60,
                "username": event["username"],
                "source_ip": event["source_ip"],
                "event_count": 1,
                "description": (
                    f"Privilege-related activity detected: "
                    f"{event_type}."
                ),
                "recommendation": (
                    "Verify the activity against authorized "
                    "administrative changes."
                ),
                "related_events": [event],
            })

        return findings

    # --------------------------------------------------
    # 4. Session monitoring
    # --------------------------------------------------

    def detect_session_activity(self, events):
        findings = []

        for event in events:
            event_type = event["event_type"]

            suspicious_session_terms = (
                "SESSION_INVALID",
                "SESSION_EXPIRED",
                "SESSION_REVOKED",
                "SESSION_REJECTED",
            )

            if not any(
                term in event_type
                for term in suspicious_session_terms
            ):
                continue

            findings.append({
                "rule": "Session Security Event",
                "severity": "MEDIUM",
                "risk_score": 55,
                "username": event["username"],
                "source_ip": event["source_ip"],
                "event_count": 1,
                "description": (
                    f"Session-related security event: {event_type}."
                ),
                "recommendation": (
                    "Review the session status and account activity."
                ),
                "related_events": [event],
            })

        return findings

    # --------------------------------------------------
    # 5. Incident correlation
    # --------------------------------------------------

    def correlate(self, findings):
        groups = defaultdict(list)

        for finding in findings:
            groups[finding["source_ip"]].append(finding)

        correlated = []

        for source_ip, group in groups.items():

            total_score = sum(
                finding["risk_score"]
                for finding in group
            )

            score = min(total_score, 100)

            if score >= 80:
                severity = "HIGH"
            elif score >= 50:
                severity = "MEDIUM"
            else:
                severity = "LOW"

            usernames = set()

            for finding in group:
                for username in finding["username"].split(", "):
                    if username != "unknown":
                        usernames.add(username)

            correlated.append({
                "source_ip": source_ip,
                "severity": severity,
                "risk_score": score,
                "rules_triggered": [
                    finding["rule"] for finding in group
                ],
                "affected_accounts": sorted(usernames),
                "finding_count": len(group),
                "findings": group,
            })

        return sorted(
            correlated,
            key=lambda incident: incident["risk_score"],
            reverse=True,
        )