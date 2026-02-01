import argparse
import os
import subprocess
import sys
from typing import Optional

from dotenv import load_dotenv

# Import watcher function
from watch_telegram import watch as watch_with_telegram


def run_cmd(cmd, cwd: Optional[str] = None) -> int:
    """
    Run command and stream output.
    """
    p = subprocess.Popen(cmd, cwd=cwd, shell=False)
    return p.wait()


def docker_compose(cmd_args, compose_dir: str) -> int:
    """
    Use 'docker compose' in the cowrie compose directory.
    """
    if not compose_dir or not os.path.isdir(compose_dir):
        print(f"[error] COWRIE_COMPOSE_DIR not found: {compose_dir}")
        return 2

    cmd = ["docker", "compose"] + cmd_args
    return run_cmd(cmd, cwd=compose_dir)


def require_env(key: str) -> str:
    val = os.environ.get(key, "").strip()
    if not val:
        print(f"[error] Missing env: {key}")
        print("Tip: set it in cli/.env then run from cli folder, or set in your shell env.")
        sys.exit(2)
    return val


def cmd_start(compose_dir: str):
    rc = docker_compose(["up", "-d"], compose_dir)
    if rc == 0:
        print("[ok] Cowrie started.")
    sys.exit(rc)


def cmd_stop(compose_dir: str):
    rc = docker_compose(["down"], compose_dir)
    if rc == 0:
        print("[ok] Cowrie stopped.")
    sys.exit(rc)


def cmd_status(compose_dir: str):
    rc = docker_compose(["ps"], compose_dir)
    sys.exit(rc)


def cmd_watch():
    log_path = require_env("COWRIE_LOG_PATH")
    token = require_env("TELEGRAM_BOT_TOKEN")
    chat_id = require_env("TELEGRAM_CHAT_ID")
    extra = os.environ.get("EXTRA_SUSPICIOUS_KEYWORDS", "")

    bruteforce_threshold = int(os.environ.get("BRUTEFORCE_THRESHOLD", "10"))
    window_seconds = int(os.environ.get("BRUTEFORCE_WINDOW_SECONDS", "120"))

    print("[info] Starting realtime watch + Telegram alerts ...")
    # replay_last=50 biar kalau kamu sudah ngetik command sebelum watch, tetap kebaca
    watch_with_telegram(
        log_path=log_path,
        bot_token=token,
        chat_id=chat_id,
        bruteforce_threshold=bruteforce_threshold,
        window_seconds=window_seconds,
        extra_keywords_csv=extra,
        replay_last=50,
        send_startup_ping=True,
        quiet=False,
    )



def cmd_report():
    """
    Call existing analyzer/analyze_cowrie.py to generate summary and CSVs.
    """
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    analyzer_path = os.path.join(base_dir, "analyzer", "analyze_cowrie.py")
    out_dir = os.path.join(base_dir, "analyzer", "out")
    logs_dir = os.path.join(base_dir, "logs")

    if not os.path.exists(analyzer_path):
        print(f"[error] Analyzer not found: {analyzer_path}")
        sys.exit(2)

    # We assume you use the upgraded analyzer that supports --logdir.
    cmd = [sys.executable, analyzer_path, "--logdir", logs_dir, "--out", out_dir]
    print("[info] Running report:", " ".join(cmd))
    rc = run_cmd(cmd, cwd=os.path.dirname(analyzer_path))
    if rc == 0:
        print(f"[ok] Report generated: {out_dir}")
        print(f"[ok] Open: {os.path.join(out_dir, 'summary.md')}")
    sys.exit(rc)


def main():
    # Load env from cli/.env if exists
    load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))

    ap = argparse.ArgumentParser(prog="impact_honey_monitor", description="Cowrie honeypot CLI: start/stop/watch/report with Telegram alerts.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("start", help="Start Cowrie via docker compose (up -d)")
    sub.add_parser("stop", help="Stop Cowrie via docker compose (down)")
    sub.add_parser("status", help="Show docker compose status (ps)")
    sub.add_parser("watch", help="Watch cowrie.json realtime and send Telegram alerts")
    sub.add_parser("report", help="Generate summary + CSVs using analyzer")

    args = ap.parse_args()

    compose_dir = os.environ.get("COWRIE_COMPOSE_DIR", "").strip()

    if args.cmd == "start":
        cmd_start(compose_dir)
    if args.cmd == "stop":
        cmd_stop(compose_dir)
    if args.cmd == "status":
        cmd_status(compose_dir)
    if args.cmd == "watch":
        cmd_watch()
        return
    if args.cmd == "report":
        cmd_report()

    ap.print_help()


if __name__ == "__main__":
    main()
