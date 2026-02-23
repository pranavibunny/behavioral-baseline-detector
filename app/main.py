import sys
import os

# Tell Python where to find our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Build correct path to data folder — goes one level up from app/ to find data/
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_FILE = os.path.join(BASE_DIR, "data", "process_logs.csv")

from simulate_logs import generate_logs, save_logs
from utils import load_logs, build_baseline
from baseline import print_baseline
from detector import detect, print_alerts

# --- CONCEPT ---
# main.py is the entry point of the entire project
# Instead of running 3 separate files, you run just this one
# It orchestrates the full pipeline:
# Generate logs → Build baseline → Detect anomalies → Print alerts

print("="*70)
print("  BEHAVIOURAL BASELINE DETECTION LAB")
print("="*70)

# Step 1 — Generate fresh logs
print("\n[1] Generating simulated endpoint logs...")
logs_raw = generate_logs(500)
save_logs(logs_raw, filename=DATA_FILE)  # passing correct path here

# Step 2 — Load and build baseline
print("\n[2] Building behavioural baseline...")
logs = load_logs(filename=DATA_FILE)  # passing correct path here
baseline = build_baseline(logs)
print_baseline(baseline)

# Step 3 — Run detection
print("\n[3] Running detection engine...")
alerts = detect(logs, baseline)
print_alerts(alerts)

print(f"\n[DONE] Total alerts: {len(alerts)} across {len(set(a['hostname'] for a in alerts))} endpoints")