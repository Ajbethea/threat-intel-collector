#!/usr/bin/env python3
import argparse, json, re, csv, os
from datetime import datetime, timedelta
from collections import defaultdict, deque

APACHE_TS_RE = re.compile(r'\[(?P<ts>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [\+\-]\d{4})\]')
SSH_TS_RE = re.compile(r'^(?P<mon>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})')
MONTHS = {"Jan":1,"Feb":2,"Mar":3,"Apr":4,"May":5,"Jun":6,
          "Jul":7,"Aug":8,"Sep":9,"Oct":10,"Nov":11,"Dec":12}

def parse_args():
    p = argparse.ArgumentParser(description="Simple Log Parser & Alerting")
    p.add_argument("--config", default="config.json", help="Path to config.json")
    p.add_argument("--report_csv", default="output/findings.csv", help="CSV summary output")
    p.add_argument("--alerts_json", default="output/alerts.json", help="Alerts JSON output")
    p.add_argument("--since", help="Only include events after this timestamp (YYYY-MM-DDTHH:MM:SS)")
    p.add_argument("--verbose", action="store_true")
    return p.parse_args()

def load_config(path):
    with open(path, "r") as f:
        cfg = json.load(f)
    for r in cfg["rules"]:
        r["_compiled"] = re.compile(r["pattern"])
    return cfg

def parse_apache_ts(line):
    m = APACHE_TS_RE.search(line)
    if not m: return None
    ts_str = m.group("ts")
    return datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S %z")

def parse_ssh_ts(line):
    m = SSH_TS_RE.search(line)
    if not m: return None
    year = datetime.utcnow().year
    mon = MONTHS.get(m.group("mon"))
    day = int(m.group("day"))
    hh,mm,ss = map(int, m.group("time").split(":"))
    return datetime(year, mon, day, hh, mm, ss)

def extract_fields(rule, line):
    m = rule["_compiled"].search(line)
    if not m: return None, {}
    fields = {}
    # attempt to map ordered groups to named fields if provided
    if "extract" in rule:
        groups = list(m.groups())
        # remove optional "invalid user " text if present as a separate group
        # We will heuristically pick last 2 groups as user, ip for SSH_FAIL pattern
        try:
            if rule["id"] == "SSH_FAIL":
                # groups: [optional 'invalid user ', user, ip]
                if len(groups) >= 2:
                    fields["user"] = groups[-2]
                    fields["ip"] = groups[-1]
            elif rule["id"] == "SSH_ROOT_LOGIN":
                fields["ip"] = groups[-1] if groups else ""
        except Exception:
            pass
    if "ip" not in fields:
        ipm = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
        if ipm: fields["ip"] = ipm.group(1)
    return m, fields

def within_window(events_deque, now_ts, window):
    cutoff = now_ts - timedelta(minutes=window)
    while events_deque and events_deque[0] < cutoff:
        events_deque.popleft()

def main():
    args = parse_args()
    cfg = load_config(args.config)

    since = None
    if args.since:
        since = datetime.strptime(args.since, "%Y-%m-%dT%H:%M:%S")

    findings = []
    counters = defaultdict(lambda: deque())
    alerts = []

    for src in cfg["sources"]:
        path = src["path"]
        typ = src["type"]
        if not os.path.exists(path):
            print(f"[WARN] Source not found: {path}")
            continue
        with open(path, "r", errors="ignore") as f:
            for raw in f:
                line = raw.rstrip("\n")
                if typ == "apache":
                    ts = parse_apache_ts(line)
                    ts_naive = ts.astimezone().replace(tzinfo=None) if ts else None
                elif typ == "ssh":
                    ts_naive = parse_ssh_ts(line)
                else:
                    ts_naive = None

                if since and ts_naive and ts_naive < since:
                    continue

                for rule in cfg["rules"]:
                    if rule["type"] != typ:
                        continue
                    m, fields = extract_fields(rule, line)
                    if not m:
                        continue
                    record = {
                        "timestamp": ts_naive.isoformat() if ts_naive else "",
                        "source": path,
                        "type": typ,
                        "rule_id": rule["id"],
                        "severity": rule["severity"],
                        "description": rule["description"],
                        "ip": fields.get("ip",""),
                        "user": fields.get("user",""),
                        "raw": line
                    }
                    findings.append(record)
                    if args.verbose:
                        print(f"[MATCH] {record['timestamp']} {rule['id']} {record['ip']} {record['user']}")

                    # Thresholds
                    for th in cfg.get("thresholds", []):
                        if th["rule_id"] != rule["id"]:
                            continue
                        group_val = record.get(th["group_by"], "")
                        if not group_val:
                            continue
                        key = (th["name"], group_val)
                        dq = counters[key]
                        now_ts = ts_naive or datetime.utcnow()
                        within_window(dq, now_ts, th["window_minutes"])
                        dq.append(now_ts)
                        if len(dq) >= th["count"]:
                            alerts.append({
                                "time": now_ts.isoformat(),
                                "threshold": th["name"],
                                "group_by": th["group_by"],
                                "group_value": group_val,
                                "rule_id": rule["id"],
                                "count_in_window": len(dq),
                                "window_minutes": th["window_minutes"],
                                "action": th["action"]
                            })
                            dq.clear()

    # Write outputs
    os.makedirs(os.path.dirname(args.report_csv), exist_ok=True)
    with open(args.report_csv, "w", newline="") as csvfile:
        fieldnames = ["timestamp","source","type","rule_id","severity","description","ip","user","raw"]
        w = csv.DictWriter(csvfile, fieldnames=fieldnames)
        w.writeheader()
        for r in findings:
            w.writerow(r)

    os.makedirs(os.path.dirname(args.alerts_json), exist_ok=True)
    with open(args.alerts_json, "w") as jf:
        json.dump(alerts, jf, indent=2)

    print(f"[OK] Findings written: {args.report_csv}")
    print(f"[OK] Alerts written:   {args.alerts_json}")
    print(f"[OK] Matches: {len(findings)}, Alerts: {len(alerts)}")

if __name__ == "__main__":
    main()
