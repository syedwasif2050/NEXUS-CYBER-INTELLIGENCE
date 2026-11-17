
from modules.log_processor import LogProcessor
from modules.threat_detector import ThreatDetector

# Load security logs
processor = LogProcessor()
processor.load_logs("data/security_logs.csv")

# Process logs
events = processor.process_logs()

# Detect threats
detector = ThreatDetector()
alerts = detector.detect_threats(events)

# Display results
print("\n===== THREAT DETECTION RESULTS =====")

for alert in alerts:
    print("\nThreat:", alert["threat"])
    print("Username:", alert["username"])
    print("Source IP:", alert["source_ip"])
    print("Severity:", alert["severity"])
    print("Details:", alert["details"])

print("\nTotal Threat Alerts:", len(alerts))
