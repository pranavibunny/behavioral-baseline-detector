from datetime import datetime

# --- SECURITY CONCEPT ---
# Risk scoring combines multiple weak signals into one strong score
# No single signal is enough — a HIGH severity alert at 9AM on a workstation
# is less urgent than a MEDIUM alert at 3AM on a domain controller
# This is exactly how Defender and SentinelOne prioritise alerts internally

# Servers are more critical than workstations
# If an attacker is on a server they have access to more resources
# lateral movement, data exfiltration, and persistence are all easier from servers
SERVER_KEYWORDS = ["SRV", "DC", "SERVER", "DOMAIN"]

def score_severity(severity):
    # Base score purely from severity label
    scores = {
        "HIGH": 50,
        "MEDIUM": 30,
        "LOW": 10
    }
    return scores.get(severity, 0)

def score_frequency(frequency):
    # --- SECURITY CONCEPT ---
    # High frequency = possible widespread attack or campaign
    # Low frequency = targeted or stealthy attack
    # Both are dangerous so we score both ends higher
    if frequency >= 20:
        return 25   # Widespread — possible campaign
    elif frequency >= 10:
        return 20   # Elevated — worth escalating
    elif frequency >= 5:
        return 15   # Moderate — monitor closely
    elif frequency == 1:
        return 20   # Single occurrence — could be targeted/stealthy
    else:
        return 10   # Low but not unique

def score_host(hostname):
    # --- SECURITY CONCEPT ---
    # Servers are higher value targets
    # Domain controllers (DC) are the most critical asset in any enterprise
    # If DC is compromised the entire organisation is compromised
    hostname_upper = hostname.upper()
    for keyword in SERVER_KEYWORDS:
        if keyword in hostname_upper:
            return 20   # Server or DC — high value target
    return 5            # Workstation — still important but lower priority

def score_time(timestamp):
    # --- SECURITY CONCEPT ---
    # Attackers often operate during off hours to avoid detection
    # 11PM to 5AM activity on an enterprise endpoint is inherently suspicious
    try:
        hour = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S").hour
        if 23 <= hour or hour <= 5:
            return 15   # Off hours — highly suspicious
        elif 6 <= hour <= 8 or 18 <= hour <= 22:
            return 5    # Early morning or evening — slightly suspicious
        else:
            return 0    # Business hours — normal
    except:
        return 0

def calculate_risk_score(alert):
    severity_score  = score_severity(alert["severity"])
    frequency_score = score_frequency(alert["frequency"])
    host_score      = score_host(alert["hostname"])
    time_score      = score_time(alert["timestamp"])

    total = severity_score + frequency_score + host_score + time_score

    # Cap at 100
    total = min(total, 100)

    return {
        "total": total,
        "breakdown": {
            "severity" : severity_score,
            "frequency": frequency_score,
            "host"     : host_score,
            "time"     : time_score
        }
    }

def get_risk_label(score):
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH RISK"
    elif score >= 40:
        return "MEDIUM RISK"
    else:
        return "LOW RISK"

if __name__ == "__main__":
    # Quick test
    test_alert = {
        "severity": "HIGH",
        "frequency": 25,
        "hostname": "SRV-DC01",
        "timestamp": "2026-02-27 02:30:00"
    }
    result = calculate_risk_score(test_alert)
    print(f"Risk Score: {result['total']}/100 — {get_risk_label(result['total'])}")
    print(f"Breakdown: {result['breakdown']}")