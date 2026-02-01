import json
import os
import time
from datetime import datetime
from typing import Optional, Dict, Any, Tuple, List

import requests
from dateutil import parser as dtparser


DEFAULT_SUSPICIOUS_KEYWORDS = [
    "wget ", "curl ", "tftp ", "chmod ", "./", "sh ", "bash ",
    "busybox", "nc ", "nohup ", "python ", "perl ", "php ",
]


def parse_time(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return dtparser.parse(ts)
    except Exception:
        return None


def send_telegram(bot_token: str, chat_id: str, text: str, timeout_s: int = 10) -> Tuple[bool, str]:
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    try:
        r = requests.post(url, data={"chat_id": chat_id, "text": text}, timeout=timeout_s)
        if r.status_code == 200:
            return True, "ok"
        return False, f"http {r.status_code}: {r.text[:200]}"
    except Exception as e:
        return False, str(e)


def build_keywords(extra_keywords_csv: str) -> List[str]:
    kws = list(DEFAULT_SUSPICIOUS_KEYWORDS)
    if extra_keywords_csv:
        for k in extra_keywords_csv.split(","):
            k = k.strip().lower()
            if k:
                kws.append(k)
    return kws


def is_suspicious_command(cmd: str, keywords: List[str]) -> bool:
    c = cmd.strip().lower()
    return any(k in c for k in keywords)


def read_last_lines(path: str, n: int) -> List[str]:
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()
    return [ln.strip() for ln in lines[-n:] if ln.strip()]


def follow_file(path: str):
    """
    Tail -f (Windows friendly). Only yields NEW appended lines after start.
    Also handles file recreation by checking size shrink.
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        open(path, "a", encoding="utf-8").close()

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(0, os.SEEK_END)
        last_pos = f.tell()

        while True:
            line = f.readline()
            if line:
                yield line
                last_pos = f.tell()
                continue

            # no new data, check rotation/recreate (size shrink)
            try:
                cur_size = os.path.getsize(path)
                if cur_size < last_pos:
                    # file truncated/recreated
                    f.close()
                    with open(path, "r", encoding="utf-8", errors="replace") as nf:
                        nf.seek(0, os.SEEK_END)
                        f = nf  # type: ignore
                        last_pos = f.tell()
            except Exception:
                pass

            time.sleep(0.25)


def watch(
    log_path: str,
    bot_token: str,
    chat_id: str,
    bruteforce_threshold: int = 10,
    window_seconds: int = 120,
    extra_keywords_csv: str = "",
    replay_last: int = 0,
    send_startup_ping: bool = True,
    quiet: bool = False,
):
    keywords = build_keywords(extra_keywords_csv)

    if send_startup_ping:
        ok, info = send_telegram(bot_token, chat_id, "✅ Impact Honey Monitor: watcher started")
        if not quiet:
            print("[telegram] startup ping:", "ok" if ok else f"failed ({info})")

    if replay_last > 0:
        if not quiet:
            print(f"[watch] replay last {replay_last} lines (to avoid missing events)")
        for ln in read_last_lines(log_path, replay_last):
            _handle_line(ln, bot_token, chat_id, keywords, bruteforce_threshold, window_seconds, quiet=quiet)

    if not quiet:
        print("[watch] log:", log_path)
        print("[watch] bruteforce threshold:", bruteforce_threshold, "in", window_seconds, "seconds")
        print("[watch] keywords:", ", ".join(keywords))
        print("----")

    # bruteforce tracking: ip -> [timestamps]
    bf: Dict[str, List[datetime]] = {}

    for line in follow_file(log_path):
        line = line.strip()
        if not line:
            continue

        # handle brute force with stateful bf
        try:
            ev: Dict[str, Any] = json.loads(line)
        except json.JSONDecodeError:
            continue

        eventid = ev.get("eventid", "unknown")
        ts = parse_time(ev.get("timestamp"))
        src_ip = ev.get("src_ip", "unknown")
        session = ev.get("session", "-")

        # suspicious commands
        if eventid == "cowrie.command.input":
            cmd = (ev.get("input") or "").strip()
            if cmd and is_suspicious_command(cmd, keywords):
                msg = f"🚨 Cowrie ALERT\nType: Suspicious Command\nIP: {src_ip}\nSession: {session}\nTime: {ts}\nCmd: {cmd}"
                ok, info = send_telegram(bot_token, chat_id, msg)
                if not quiet:
                    print("[ALERT]", msg.replace("\n", " | "))
                    if not ok:
                        print("[telegram-error]", info)

        # brute force burst
        if eventid == "cowrie.login.failed":
            if ts is None:
                continue
            bf.setdefault(src_ip, []).append(ts)
            cutoff = ts.timestamp() - window_seconds
            bf[src_ip] = [t for t in bf[src_ip] if t.timestamp() >= cutoff]

            if len(bf[src_ip]) >= bruteforce_threshold:
                msg = f"🚨 Cowrie ALERT\nType: Brute Force Suspected\nIP: {src_ip}\nTime: {ts}\nFails: {len(bf[src_ip])} in {window_seconds}s"
                ok, info = send_telegram(bot_token, chat_id, msg)
                if not quiet:
                    print("[ALERT]", msg.replace("\n", " | "))
                    if not ok:
                        print("[telegram-error]", info)
                bf[src_ip].clear()


def _handle_line(line: str, bot_token: str, chat_id: str, keywords: List[str],
                 bruteforce_threshold: int, window_seconds: int, quiet: bool = False):
    # simple stateless handler used only for replay; brute force state not replayed
    try:
        ev: Dict[str, Any] = json.loads(line)
    except json.JSONDecodeError:
        return
    if ev.get("eventid") != "cowrie.command.input":
        return
    cmd = (ev.get("input") or "").strip()
    if cmd and is_suspicious_command(cmd, keywords):
        msg = f"🚨 Cowrie ALERT (replay)\nCmd: {cmd}\nIP: {ev.get('src_ip','unknown')}\nTime: {ev.get('timestamp')}"
        ok, info = send_telegram(bot_token, chat_id, msg)
        if not quiet:
            print("[REPLAY ALERT]", msg.replace("\n", " | "))
            if not ok:
                print("[telegram-error]", info)
