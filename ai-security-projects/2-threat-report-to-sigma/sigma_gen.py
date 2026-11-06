"""Threat report -> Sigma rules -> validated against test events.
Step 1: find ATT&CK techniques in report text. Step 2: generate Sigma rules.
Step 3: run the rules on labelled events and report true/false positives (the proof)."""
import json, sys

KB = {
    "T1110": {"name": "Brute Force", "words": ["brute force", "password spray", "failed login", "credential stuffing"],
              "logsource": {"product": "linux", "service": "auth"},
              "field": "message", "value": "Failed password", "tactic": "credential_access"},
    "T1059.001": {"name": "PowerShell Encoded Command", "words": ["powershell", "encodedcommand", "encoded command"],
              "logsource": {"category": "process_creation", "product": "windows"},
              "field": "CommandLine", "value": " -enc ", "tactic": "execution"},
    "T1053.005": {"name": "Scheduled Task Creation", "words": ["scheduled task", "schtasks", "persistence via task"],
              "logsource": {"category": "process_creation", "product": "windows"},
              "field": "CommandLine", "value": "schtasks /create", "tactic": "persistence"},
    "T1105": {"name": "Ingress Tool Transfer via certutil", "words": ["certutil", "download payload", "tool transfer"],
              "logsource": {"category": "process_creation", "product": "windows"},
              "field": "CommandLine", "value": "certutil -urlcache", "tactic": "command_and_control"},
}

def find_techniques(text):
    t = text.lower()
    return [tid for tid, k in KB.items() if any(w in t for w in k["words"])]

def to_sigma(tid):
    k = KB[tid]
    ls = "\n".join(f"  {a}: {b}" for a, b in k["logsource"].items())
    return (f"title: {k['name']}\nstatus: experimental\n"
            f"description: Auto-generated from a threat report. Review before production use.\n"
            f"logsource:\n{ls}\ndetection:\n  selection:\n    {k['field']}|contains: '{k['value']}'\n"
            f"  condition: selection\nlevel: medium\ntags:\n  - attack.{k['tactic']}\n  - attack.{tid.lower()}\n")

def matches(tid, event):
    k = KB[tid]
    return k["value"].lower() in str(event.get(k["field"], "")).lower()

def validate(tids, events):
    for tid in tids:
        tp = sum(1 for e in events if matches(tid, e) and e["malicious"] and e["technique"] == tid)
        fp = sum(1 for e in events if matches(tid, e) and not e["malicious"])
        fn = sum(1 for e in events if not matches(tid, e) and e["malicious"] and e["technique"] == tid)
        print(f"{tid} {KB[tid]['name']}: true positives={tp}, false positives={fp}, missed={fn}")

if __name__ == "__main__":
    report = open(sys.argv[1] if len(sys.argv) > 1 else "sample_report.txt").read()
    events = [json.loads(l) for l in open("test_events.jsonl") if l.strip()]
    tids = find_techniques(report)
    print("Techniques found:", ", ".join(tids) or "none", "\n")
    for tid in tids:
        print(f"--- rule for {tid} ---\n{to_sigma(tid)}")
    print("=== Validation on test events ===")
    validate(tids, events)
