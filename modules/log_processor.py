
# =================================================
# SMART CYBER THREAT DETECTION SYSTEM
# MODULE: SECURITY LOG PROCESSOR
# =================================================

import pandas as pd

from modules.data_structures import Queue
from modules.data_structures import SinglyLinkedList


class LogProcessor:

    def __init__(self):
        self.event_queue = Queue()
        self.event_list = SinglyLinkedList()
        self.logs = None

    # Read CSV file
    def load_logs(self, file_path):

        try:
            self.logs = pd.read_csv(file_path)

            required_columns = [
                "timestamp",
                "username",
                "source_ip",
                "event_type",
                "status"
            ]

            for column in required_columns:
                if column not in self.logs.columns:
                    raise ValueError(
                        f"Missing column: {column}"
                    )

            self.logs["timestamp"] = pd.to_datetime(
                self.logs["timestamp"],
                errors="coerce"
            )

            self.logs = self.logs.dropna(
                subset=required_columns
            ).copy()

            return self.logs

        except FileNotFoundError:
            print("Error: CSV file not found.")
            return None

        except Exception as error:
            print("Error loading logs:", error)
            return None

    # Process security events
    def process_logs(self):

        if self.logs is None:
            return []

        processed_events = []

        for _, row in self.logs.iterrows():

            event = {
                "timestamp": row["timestamp"],
                "username": str(row["username"]),
                "source_ip": str(row["source_ip"]),
                "event_type": str(row["event_type"]),
                "status": str(row["status"])
            }

            # Add event to Queue
            self.event_queue.enqueue(event)

        # Process Queue
        while not self.event_queue.is_empty():

            event = self.event_queue.dequeue()

            self.event_list.insert(event)

            processed_events.append(event)

        return processed_events

    # Return processed event count
    def total_events(self):

        return len(self.logs) if self.logs is not None else 0
