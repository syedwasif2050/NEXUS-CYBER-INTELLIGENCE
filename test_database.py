
from modules.log_processor import LogProcessor
from modules.incident_correlator import IncidentCorrelator
from modules.database_manager import DatabaseManager

processor = LogProcessor()
processor.load_logs("data/security_logs.csv")
events = processor.process_logs()

correlator = IncidentCorrelator()
incidents = correlator.correlate_events(events)

db = DatabaseManager()
db.save_logs(events)
db.save_incidents(incidents)

print("===== DATABASE RESULTS =====")
print("Saved Logs:", len(db.get_logs()))
print("Saved Incidents:", len(db.get_incidents()))

db.close()
