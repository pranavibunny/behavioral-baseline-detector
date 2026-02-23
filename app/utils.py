import csv
from collections import defaultdict

# --- CONCEPT ---
# This is a shared utility module
# Instead of copy pasting load_logs and build_baseline in every file
# we write it once here and import it wherever needed

def load_logs(filename="../data/process_logs.csv"):
    logs = []
    with open(filename, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            logs.append(row)
    print(f"Loaded {len(logs)} log entries")
    return logs

def build_baseline(logs):
    baseline = defaultdict(int)
    for log in logs:
        pair = (log["parent_process"], log["child_process"])
        baseline[pair] += 1
    return baseline