# Behavioural Baseline Detection Engine

## Why I built this

I work in endpoint security. Three years of managing Microsoft Defender, SentinelOne, CrowdStrike across large enterprise environments — 50,000+ endpoints, multiple clients, real incidents.

But here's the honest truth. Most of my day is compliance monitoring, health checks, deployments, and exclusion management. When an alert fires I investigate it, but I never really understood what was happening *underneath* — how the tool actually decided something was suspicious in the first place.

I wanted to understand that. Not just use the tool but understand the thinking behind it.

So I started building my own version from scratch.

---

## What this project is

A Python-based detection engine that simulates how EDR tools analyse process behaviour to find threats.

Every time a process runs on an endpoint it launches from somewhere — a parent process. Explorer opens Chrome. Word opens Excel. These relationships are normal and predictable. But when Word suddenly opens PowerShell, or Excel spawns CMD — that's where attacks hide.

This project builds a baseline of normal process relationships, then flags anything that deviates from it. That's the core idea behind behavioural detection in tools like Microsoft Defender for Endpoint and SentinelOne.

---

## What I learned building this

The thing that surprised me most was understanding why **frequency alone doesn't tell you if something is malicious**.

I always thought — if a pattern happens a lot it must be normal, if it happens once it must be suspicious. Working through this project I realised that's completely wrong:

- A suspicious pattern happening 200 times means a campaign — malware spread company wide
- A suspicious pattern happening once means a targeted attack — someone going after one specific machine

Both are dangerous. Just in different ways. That changes how you respond.

The other thing that clicked was **MITRE ATT&CK mapping**. I knew MITRE existed but I never connected it to real alert logic. Building it into the detection engine made me realise — every alert in Defender has a technique behind it. T1566 isn't just a label, it's the actual attack pattern the tool recognised. That changes how you read alerts.

---

## Where this is going

Right now this covers process behaviour — parent-child relationships, frequency analysis, MITRE mapping, and risk scoring.

But real EDR tools go much deeper. I'm building this out phase by phase to cover:

- PowerShell obfuscation detection — encoded commands, suspicious flags
- File system anomaly detection — mass modifications, executables in temp folders
- Network behaviour — processes making unexpected outbound connections
- Registry persistence detection — run keys, scheduled tasks
- A full dashboard that ties all signals together into one view

The goal is to rebuild the detection logic of a real EDR engine from scratch — not to replace commercial tools, but to deeply understand how they think. Because understanding the tool makes you better at using it.

---

## Project structure

```
behavioral-baseline-detector/
│
├── app/
│   ├── main.py              # Runs the full pipeline
│   ├── simulate_logs.py     # Generates synthetic endpoint process logs
│   ├── utils.py             # Shared functions — load logs, build baseline
│   ├── baseline.py          # Builds frequency baseline of normal behaviour
│   └── detector.py          # Detection engine with MITRE ATT&CK mapping
│
├── data/                    # Generated log data (auto-created on first run)
└── README.md
```

---

## How to run

```bash
# Run the full pipeline
python app/main.py
```

This will generate 500 simulated endpoint process logs, build a behavioural baseline, run the detection engine, and print alerts with MITRE mapping and risk scores.

---

## Detection coverage so far

| Attack Pattern | MITRE Technique | Severity |
|---|---|---|
| winword.exe → powershell.exe | T1566.001 Phishing: Malicious Office Document | HIGH |
| excel.exe → cmd.exe | T1059.003 Command and Scripting: Windows CMD | HIGH |
| outlook.exe → powershell.exe | T1566.001 Phishing: Malicious Office Document | HIGH |
| powershell.exe → cmd.exe | T1059.001 Command and Scripting: PowerShell | MEDIUM |
| svchost.exe → powershell.exe | T1036 Masquerading | MEDIUM |

---

## Progress

- [x] Phase 1 — Simulate endpoint process logs
- [x] Phase 2 — Build behavioural baseline
- [x] Phase 3 — Detection engine with MITRE ATT&CK mapping
- [ ] Phase 4 — Risk scoring (0-100)
- [ ] Phase 5 — PowerShell obfuscation detection
- [ ] Phase 6 — File system anomaly detection
- [ ] Phase 7 — Network behaviour detection
- [ ] Phase 8 — Registry persistence detection
- [ ] Phase 9 — Full multi-signal dashboard

---

## Background

3+ years in endpoint security at enterprise scale. This project is how I'm going deeper.

Built with Python. Actively in progress.
