import csv
import random
from datetime import datetime, timedelta

# --- SECURITY CONCEPT ---
# In real EDR tools, every process that runs on an endpoint generates a log
# That log contains: which process ran, who launched it (parent), when, and on which machine
# We are simulating exactly that kind of log data

# These are NORMAL parent-child relationships you'd see in any enterprise environment
# Think of this as your "known good" baseline — what you see every day at Ahold
NORMAL_BEHAVIOURS = [
    ("explorer.exe", "chrome.exe"),       # User opens Chrome from desktop
    ("explorer.exe", "notepad.exe"),      # User opens Notepad
    ("services.exe", "svchost.exe"),      # Windows service manager launching services
    ("svchost.exe", "wmiprvse.exe"),      # WMI provider — very common in enterprises
    ("explorer.exe", "outlook.exe"),      # User opens Outlook
    ("outlook.exe", "winword.exe"),       # Opening Word document from email
    ("explorer.exe", "winword.exe"),      # Opening Word directly
    ("winword.exe", "excel.exe"),         # Word opening Excel
]

# These are SUSPICIOUS parent-child relationships
# These are the kind of alerts you'd investigate in Defender or SentinelOne
SUSPICIOUS_BEHAVIOURS = [
    ("winword.exe", "powershell.exe"),    # Word launching PowerShell = macro attack
    ("excel.exe", "cmd.exe"),            # Excel launching CMD = suspicious macro
    ("outlook.exe", "powershell.exe"),   # Outlook launching PowerShell = phishing
    ("powershell.exe", "cmd.exe"),       # PowerShell spawning CMD = evasion chain
    ("svchost.exe", "powershell.exe"),   # Service launching PowerShell = lateral movement
]

# Hostnames simulating an enterprise environment — like your Ahold endpoints
HOSTS = ["WKSTN-001", "WKSTN-042", "WKSTN-107", "SRV-DC01", "SRV-FILE02"]

def generate_logs(total_logs=500):
    logs = []
    base_time = datetime.now()

    for i in range(total_logs):
        # 90% of the time generate normal behaviour — just like real environments
        # 10% of the time inject something suspicious
        if random.random() < 0.90:
            parent, child = random.choice(NORMAL_BEHAVIOURS)
            is_suspicious = False
        else:
            parent, child = random.choice(SUSPICIOUS_BEHAVIOURS)
            is_suspicious = True

        log = {
            "timestamp": (base_time + timedelta(minutes=i)).strftime("%Y-%m-%d %H:%M:%S"),
            "hostname": random.choice(HOSTS),
            "parent_process": parent,
            "child_process": child,
            "is_suspicious": is_suspicious   # We'll use this later to test our detection accuracy
        }
        logs.append(log)

    return logs

def save_logs(logs, filename=None):
    if filename is None:
        filename = "data\\process_logs.csv"
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=logs[0].keys())
        writer.writeheader()
        writer.writerows(logs)
    print(f"Generated {len(logs)} log entries and saved to {filename}")

