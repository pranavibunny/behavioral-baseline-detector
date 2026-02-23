from utils import load_logs, build_baseline

# --- CONCEPT ---
# We import shared functions from utils.py
# baseline.py now only has ONE job — print the baseline table

def print_baseline(baseline):
    print("\n--- BASELINE: Normal Process Relationships ---")
    print(f"{'Parent':<25} {'Child':<25} {'Count':<10}")
    print("-" * 60)

    sorted_baseline = sorted(baseline.items(), key=lambda x: x[1], reverse=True)

    for (parent, child), count in sorted_baseline:
        print(f"{parent:<25} {child:<25} {count:<10}")

