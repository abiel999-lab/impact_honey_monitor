import argparse
import json
import os
import time
from datetime import datetime
from typing import Optional, Dict, Any

from dateutil import parser as dtparser


SUSPICIOUS_KEYWORDS = (
    "wget ", "curl ", "tftp ", "chmod ", "./", "sh ", "bash ",
    "busybox", "nc ", "nohup ", "python ", "perl ", "php ",
)


def parse_time(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return dtparser.parse(ts)
    except Exception:
        return None


def is_suspicious_command(cmd: str) -> bool:
    c = cmd.strip().lower()
    return any(k in c for k in SUSPICIOUS_KEYWORDS)


def tail_f(path: str):
    """
    Follow a file like `tail -f` in Python (Windows-friendly).
    """
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.25)
                continue
            yield line


def main():
    ap = argparse.ArgumentParser(description="Realtime monitor Cowrie JSON log and print alerts.")
    ap.add_argument("--log", required=True, help="Path to cowrie.json")
    ap.add_argument("--bruteforce-threshold", type=int, default=10,
                    help="Alert if same src_ip has >= N login.failed events within a short window.")
    ap.add_argument("--window-seconds", type=int, default=120,
                    help="Time window for bruteforce counting.")
    args = ap.parse_args()

    if not os.path.exists(args.log):
        raise SystemExit(f"Log file not found: {args.log}")

    # bruteforce tracking: ip -> [timestamps]
    bf: Dict[str, list[datetime]] = {}

    print("[watch_alert] Watching:", args.log)
    print("[watch_alert] Suspicious keywords:", ", ".join(SUSPICIOUS_KEYWORDS))
    print("[watch_alert] Bruteforce threshold:", args.bruteforce_threshold, "in", args.window_seconds, "seconds")
    print("----")

    for line in tail_f(args.log):
        line = line.strip()
        if not line:
            continue

        try:
            ev: Dict[str, Any] = json.loads(line)
        except json.JSONDecodeError:
            continue

        eventid = ev.get("eventid", "unknown")
        ts = parse_time(ev.get("timestamp"))
        src_ip = ev.get("src_ip", "unknown")
        session = ev.get("session", "-")

        # 1) Alert on suspicious commands
        if eventid == "cowrie.command.input":
            cmd = (ev.get("input") or "").strip()
            if cmd and is_suspicious_command(cmd):
                print(f"[ALERT][{ts}] suspicious command from {src_ip} (session {session}): {cmd}")

        # 2) Alert on brute force bursts
        if eventid == "cowrie.login.failed":
            if ts is None:
                continue
            bf.setdefault(src_ip, []).append(ts)

            # keep only timestamps within window
            cutoff = ts.timestamp() - args.window_seconds
            bf[src_ip] = [t for t in bf[src_ip] if t.timestamp() >= cutoff]

            if len(bf[src_ip]) >= args.bruteforce_threshold:
                print(f"[ALERT][{ts}] brute force suspected from {src_ip}: "
                      f"{len(bf[src_ip])} failed logins in {args.window_seconds}s")
                # reset after alert to avoid spam
                bf[src_ip].clear()


if __name__ == "__main__":
    main()
