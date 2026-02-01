import argparse
import csv
import glob
import json
import os
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, Any, Iterable, Tuple, Optional, List

from dateutil import parser as dtparser


def safe_get(d: Dict[str, Any], *keys, default=None):
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


def parse_time(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return dtparser.parse(ts)
    except Exception:
        return None


def iter_cowrie_json_lines(path: str) -> Iterable[Dict[str, Any]]:
    """
    Cowrie JSON log is usually JSON lines (one JSON object per line).
    """
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                # If a line isn't JSON, skip it safely
                continue


def discover_log_files(log_path: Optional[str], log_dir: Optional[str]) -> List[str]:
    """
    Find cowrie JSON logs.
    Priority:
      1) explicit --log file
      2) --logdir folder -> cowrie.json + cowrie.json.* (rotated)
    """
    candidates: List[str] = []

    if log_path:
        if os.path.isfile(log_path):
            return [log_path]
        return []  # explicit given but not found

    if log_dir:
        if not os.path.isdir(log_dir):
            return []
        # Common patterns
        patterns = [
            os.path.join(log_dir, "cowrie.json"),
            os.path.join(log_dir, "cowrie.json.*"),
            os.path.join(log_dir, "cowrie*.json"),
            os.path.join(log_dir, "cowrie*.json.*"),
        ]
        for p in patterns:
            candidates.extend(glob.glob(p))

        # Keep only files, sort newest first (by mtime)
        candidates = [c for c in candidates if os.path.isfile(c)]
        candidates.sort(key=lambda x: os.path.getmtime(x), reverse=True)

    return candidates


def write_top_csv(path: str, header: Tuple[str, str], rows: Iterable[Tuple[str, int]]):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(list(header))
        for k, v in rows:
            w.writerow([k, v])


def md_table(title: str, rows: Iterable[Tuple[str, int]], col1: str, col2: str, limit: int = 10) -> str:
    rows = list(rows)[:limit]
    out = []
    out.append(f"### {title}\n")
    out.append(f"| {col1} | {col2} |")
    out.append("|---|---:|")
    for k, v in rows:
        out.append(f"| `{k}` | {v} |")
    out.append("")
    return "\n".join(out)


def analyze(log_files: List[str], out_dir: str, top_n: int, since: Optional[datetime], until: Optional[datetime]):
    by_ip = Counter()
    by_username = Counter()
    by_password = Counter()
    by_command = Counter()
    by_eventid = Counter()
    by_country = Counter()

    first_seen_ip: Dict[str, datetime] = {}
    last_seen_ip: Dict[str, datetime] = {}
    ip_to_commands: Dict[str, Counter] = defaultdict(Counter)

    total_events = 0
    total_sessions = set()

    for log_path in log_files:
        for ev in iter_cowrie_json_lines(log_path):
            ts = parse_time(ev.get("timestamp"))
            if ts is None:
                continue

            if since and ts < since:
                continue
            if until and ts > until:
                continue

            total_events += 1

            eventid = ev.get("eventid", "unknown")
            by_eventid[eventid] += 1

            src_ip = ev.get("src_ip") or safe_get(ev, "src", "ip") or "unknown"
            by_ip[src_ip] += 1

            if src_ip not in first_seen_ip or ts < first_seen_ip[src_ip]:
                first_seen_ip[src_ip] = ts
            if src_ip not in last_seen_ip or ts > last_seen_ip[src_ip]:
                last_seen_ip[src_ip] = ts

            sid = ev.get("session")
            if sid:
                total_sessions.add(sid)

            if eventid in ("cowrie.login.failed", "cowrie.login.success"):
                username = ev.get("username") or "unknown"
                password = ev.get("password") or "unknown"
                by_username[username] += 1
                by_password[password] += 1

            if eventid == "cowrie.command.input":
                inp = (ev.get("input") or "").strip()
                if inp:
                    by_command[inp] += 1
                    ip_to_commands[src_ip][inp] += 1

            country = safe_get(ev, "geoip", "country_name") or safe_get(ev, "geoip", "country_code") or None
            if country:
                by_country[country] += 1

    os.makedirs(out_dir, exist_ok=True)

    write_top_csv(os.path.join(out_dir, "top_ips.csv"), ("ip", "count"), by_ip.most_common(top_n))
    write_top_csv(os.path.join(out_dir, "top_usernames.csv"), ("username", "count"), by_username.most_common(top_n))
    write_top_csv(os.path.join(out_dir, "top_passwords.csv"), ("password", "count"), by_password.most_common(top_n))
    write_top_csv(os.path.join(out_dir, "top_commands.csv"), ("command", "count"), by_command.most_common(top_n))
    write_top_csv(os.path.join(out_dir, "top_eventids.csv"), ("eventid", "count"), by_eventid.most_common(top_n))
    if by_country:
        write_top_csv(os.path.join(out_dir, "top_countries.csv"), ("country", "count"), by_country.most_common(top_n))

    start_str = since.isoformat() if since else "ALL"
    end_str = until.isoformat() if until else "ALL"

    summary = []
    summary.append("# impact_honey_monitor — Cowrie Attack Summary\n")
    summary.append("## 1. Input\n")
    summary.append(f"- Logs analyzed ({len(log_files)} file):")
    for p in log_files[:10]:
        summary.append(f"  - `{p}`")
    if len(log_files) > 10:
        summary.append(f"  - ...and {len(log_files) - 10} more")
    summary.append(f"- Time filter: `{start_str}` → `{end_str}`")
    summary.append(f"- Total events analyzed: **{total_events}**")
    summary.append(f"- Unique sessions: **{len(total_sessions)}**")
    summary.append(f"- Unique source IPs: **{len(by_ip)}**\n")

    summary.append("## 2. High-level patterns\n")
    summary.append(md_table("Top Source IPs", by_ip.most_common(top_n), "IP", "Hits", limit=10))

    if by_username:
        summary.append(md_table("Top Usernames Tried", by_username.most_common(top_n), "Username", "Attempts", limit=10))
    if by_password:
        summary.append(md_table("Top Passwords Tried", by_password.most_common(top_n), "Password", "Attempts", limit=10))

    summary.append(md_table("Top Commands Entered", by_command.most_common(top_n), "Command", "Count", limit=10))
    summary.append(md_table("Top Event Types (eventid)", by_eventid.most_common(top_n), "EventID", "Count", limit=10))

    if by_country:
        summary.append(md_table("Top Countries (if available)", by_country.most_common(top_n), "Country", "Count", limit=10))

    summary.append("## 3. IP behavior signatures (top 5 IPs)\n")
    for ip, _cnt in by_ip.most_common(5):
        fs = first_seen_ip.get(ip)
        ls = last_seen_ip.get(ip)
        top_cmds = ip_to_commands[ip].most_common(5)
        summary.append(f"### IP `{ip}`")
        summary.append(f"- First seen: `{fs.isoformat() if fs else 'unknown'}`")
        summary.append(f"- Last seen: `{ls.isoformat() if ls else 'unknown'}`")
        if top_cmds:
            summary.append("- Top commands:")
            for cmd, c in top_cmds:
                summary.append(f"  - `{cmd}` ({c}x)")
        else:
            summary.append("- Top commands: (none recorded)")
        summary.append("")

    summary.append("## 4. Quick analyst notes (heuristics)\n")
    notes = []

    login_fail = by_eventid.get("cowrie.login.failed", 0)
    login_succ = by_eventid.get("cowrie.login.success", 0)
    if login_fail > 0:
        notes.append(f"- Detected **{login_fail}** login failures → likely **brute force / credential stuffing**.")
    if login_succ > 0:
        notes.append(f"- Detected **{login_succ}** login successes (Cowrie fake) → attacker proceeded to interactive stage.")

    suspicious_keywords = ("wget ", "curl ", "tftp ", "chmod ", "./", "sh ", "bash ", "busybox", "nc ", "nohup ")
    suspicious_cmds = [cmd for cmd, _ in by_command.items() if any(k in cmd for k in suspicious_keywords)]
    if suspicious_cmds:
        notes.append(f"- Found commands that look like **malware dropper / execution** (e.g. wget/curl/chmod). Count: {len(suspicious_cmds)}")

    if not notes:
        notes.append("- No strong heuristic flags from commands (or command logging not present).")

    summary.extend(notes)
    summary.append("")

    summary_path = os.path.join(out_dir, "summary.md")
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write("\n".join(summary))

    print("Done.")
    print(f"Summary: {summary_path}")
    print(f"CSVs: {out_dir}")


def main():
    ap = argparse.ArgumentParser(description="Analyze Cowrie JSON logs and output threat-intel style summaries.")
    ap.add_argument("--log", default=None, help="Path to a single cowrie.json (JSON lines). Optional.")
    ap.add_argument("--logdir", default=None, help="Directory containing cowrie logs (recommended). Optional.")
    ap.add_argument("--out", default="out", help="Output directory.")
    ap.add_argument("--top", type=int, default=50, help="Top N for CSV ranking outputs.")
    ap.add_argument("--since", default=None, help="ISO time filter start (e.g. 2026-01-31T00:00:00).")
    ap.add_argument("--until", default=None, help="ISO time filter end (e.g. 2026-01-31T23:59:59).")
    args = ap.parse_args()

    since = parse_time(args.since) if args.since else None
    until = parse_time(args.until) if args.until else None

    log_files = discover_log_files(args.log, args.logdir)
    if not log_files:
        if args.log:
            raise SystemExit(f"Log file not found: {args.log}")
        if args.logdir:
            raise SystemExit(f"No cowrie json logs found in directory: {args.logdir}")
        raise SystemExit("Provide --log or --logdir")

    analyze(log_files, args.out, args.top, since, until)


if __name__ == "__main__":
    main()
