from modules.log_processor import LogProcessor

processor = LogProcessor()

logs = processor.load_logs("data/security_logs.csv")

if logs is not None:

    print("\n===== SECURITY LOGS =====")

    print(logs.to_string(index=False))

    events = processor.process_logs()

    print("\n===== PROCESSING RESULT =====")

    print("Total Events:", processor.total_events())

    print("Processed Events:", len(events))

    print("\n===== FIRST PROCESSED EVENT =====")

    if events:
        print(events[0])