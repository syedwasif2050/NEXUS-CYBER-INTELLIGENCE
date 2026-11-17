
from modules.log_processor import LogProcessor
from modules.incident_correlator import IncidentCorrelator
from modules.sorting_algorithms import SortingAlgorithms

# Load and process logs
processor = LogProcessor()
processor.load_logs("data/security_logs.csv")
events = processor.process_logs()

# Generate incidents
correlator = IncidentCorrelator()
incidents = correlator.correlate_events(events)

# Create sorting object
sorter = SortingAlgorithms()

# Test all five algorithms
algorithms = {
    "Bubble Sort": sorter.bubble_sort,
    "Insertion Sort": sorter.insertion_sort,
    "Merge Sort": sorter.merge_sort,
    "Shell Sort": sorter.shell_sort,
    "Heap Sort": sorter.heap_sort
}

print("\n===== INCIDENT SORTING RESULTS =====")

for name, algorithm in algorithms.items():

    sorted_incidents = algorithm(incidents)

    print(f"\n{name}:")

    for incident in sorted_incidents:
        print(
            incident["username"],
            "-",
            incident["severity"],
            "-",
            incident["incident_type"]
        )
