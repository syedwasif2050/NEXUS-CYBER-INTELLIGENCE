
from modules.log_processor import LogProcessor
from modules.incident_correlator import IncidentCorrelator

# Load and process logs
processor = LogProcessor()
processor.load_logs("data/security_logs.csv")
events = processor.process_logs()

# Correlate incidents
correlator = IncidentCorrelator()
incidents = correlator.correlate_events(events)

# Display incidents
print("\n===== INCIDENT CORRELATION RESULTS =====")

for incident in incidents:

    print("\nIncident:", incident["incident_type"])
    print("Username:", incident["username"])
    print("Source IP:", incident["source_ip"])
    print("Severity:", incident["severity"])
    print("Related Events:", incident["related_events"])
    print("Failed Logins:", incident["failed_logins"])
    print("Successful Logins:", incident["successful_logins"])

print("\nTotal Incidents:", len(incidents))
