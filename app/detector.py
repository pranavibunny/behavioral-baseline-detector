from utils import load_logs, build_baseline
from risk_scorer import calculate_risk_score, get_risk_label


# --- SECURITY CONCEPT ---
# MITRE ATT&CK mapping — each suspicious pair maps to a real attack technique

KNOWN_SUSPICIOUS = {
    ("winword.exe", "powershell.exe"): {
        "reason": "Word launching PowerShell — common macro-based attack",
        "mitre": "T1566.001 — Phishing: Malicious Office Document",
        "severity": "HIGH"
    },
    ("excel.exe", "cmd.exe"): {
        "reason": "Excel launching CMD — malicious macro execution",
        "mitre": "T1059.003 — Command and Scripting: Windows CMD",
        "severity": "HIGH"
    },
    ("outlook.exe", "powershell.exe"): {
        "reason": "Outlook launching PowerShell — phishing email execution",
        "mitre": "T1566.001 — Phishing: Malicious Office Document",
        "severity": "HIGH"
    },
    ("powershell.exe", "cmd.exe"): {
        "reason": "PowerShell spawning CMD — evasion or lateral movement",
        "mitre": "T1059.001 — Command and Scripting: PowerShell",
        "severity": "MEDIUM"
    },
    ("svchost.exe", "powershell.exe"): {
        "reason": "Service launching PowerShell — potential lateral movement",
        "mitre": "T1036 — Masquerading",
        "severity": "MEDIUM"
    },
}

def detect(logs, baseline):
    from risk_scorer import calculate_risk_score, get_risk_label
    
    alerts = []

    for log in logs:
        parent = log["parent_process"]
        child = log["child_process"]
        pair = (parent, child)

        if pair in KNOWN_SUSPICIOUS:
            threat = KNOWN_SUSPICIOUS[pair]
            
            frequency = baseline[pair]
            
            risk = calculate_risk_score({
                "severity": threat["severity"],
                "frequency": frequency,
                "hostname": log["hostname"],
                "timestamp": log["timestamp"]
            })

            alert = {
                "timestamp": log["timestamp"],
                "hostname": log["hostname"],
                "parent_process": parent,
                "child_process": child,
                "reason": threat["reason"],
                "mitre": threat["mitre"],
                "severity": threat["severity"],
                "frequency": frequency,
                "frequency_note": "Widespread — possible campaign" if frequency > 15 else "Low frequency — targeted or stealthy",
                "risk_score": risk["total"],
                "risk_label": get_risk_label(risk["total"]),
                "score_breakdown": risk["breakdown"]
            }
            alerts.append(alert)

    # Deduplicate
    seen = set()
    unique_alerts = []
    for alert in alerts:
        key = (alert["hostname"], alert["parent_process"], alert["child_process"])
        if key not in seen:
            seen.add(key)
            unique_alerts.append(alert)

    return unique_alerts


def print_alerts(alerts):
    if not alerts:
        print("No suspicious activity detected.")
        return

    print(f"\n{'='*70}")
    print(f"  BEHAVIOURAL DETECTION ENGINE — {len(alerts)} ALERTS FOUND")
    print(f"{'='*70}")

    # Sort by risk score — highest first
    sorted_alerts = sorted(alerts, key=lambda x: x["risk_score"], reverse=True)

    for i, alert in enumerate(sorted_alerts, 1):
        print(f"\n[ALERT {i}] Severity: {alert['severity']} — {alert['risk_label']}")
        print(f"  Time       : {alert['timestamp']}")
        print(f"  Host       : {alert['hostname']}")
        print(f"  Parent     : {alert['parent_process']}")
        print(f"  Child      : {alert['child_process']}")
        print(f"  Reason     : {alert['reason']}")
        print(f"  MITRE      : {alert['mitre']}")
        print(f"  Frequency  : {alert['frequency']} occurrences — {alert['frequency_note']}")
        print(f"  Risk Score : {alert['risk_score']}/100")
        print(f"  Breakdown  → Severity: {alert['score_breakdown']['severity']} | Frequency: {alert['score_breakdown']['frequency']} | Host: {alert['score_breakdown']['host']} | Time: {alert['score_breakdown']['time']}")
        print(f"  Action     : {'Investigate immediately' if alert['severity'] == 'HIGH' else 'Monitor and correlate with other signals'}")
        print(f"  {'-'*60}")
        