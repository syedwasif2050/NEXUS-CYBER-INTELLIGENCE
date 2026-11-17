
import time

from modules.log_processor import LogProcessor
from modules.incident_correlator import IncidentCorrelator
from modules.sorting_algorithms import SortingAlgorithms

# Load data
processor = LogProcessor()
processor.load_logs("data/security_logs.csv")
events = processor.process_logs()

# Generate incidents
correlator = IncidentCorrelator()
incidents = correlator.correlate_events(events)

# Sorting algorithms
algorithms = {
    "Bubble Sort": SortingAlgorithms.bubble_sort,
    "Insertion Sort": SortingAlgorithms.insertion_sort,
    "Merge Sort": SortingAlgorithms.merge_sort,
    "Shell Sort": SortingAlgorithms.shell_sort,
    "Heap Sort": SortingAlgorithms.heap_sort
}

print("\n===== SORTING PERFORMANCE COMPARISON =====")

for name, algorithm in algorithms.items():

    start = time.perf_counter()

    for _ in range(1000):
        algorithm(incidents)

    end = time.perf_counter()

    execution_time = (end - start) / 1000

    print(f"{name}: {execution_time * 1000:.6f} ms")
