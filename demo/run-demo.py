#!/usr/bin/env python3
"""mcp-guard demo driver — runs real tools over MCP stdio and pretty-prints
the output with pacing suitable for a screen recording.

Usage:  python3 run-demo.py /path/to/mcp-guard-binary
"""
import json
import subprocess
import sys
import time
import os
import tempfile
import atexit
import shutil

BINARY = sys.argv[1] if len(sys.argv) > 1 else "mcp-guard"


def make_sample_app():
    """Generate an ephemeral sample project with planted FAKE secrets so the
    scan tools have real findings to show. Cleaned up on exit — nothing
    touches the repo."""
    d = tempfile.mkdtemp(prefix="mcp-guard-demo-")
    atexit.register(lambda: shutil.rmtree(d, ignore_errors=True))
    os.makedirs(os.path.join(d, "src"), exist_ok=True)
    # All values below are FAKE demo credentials. They are assembled from
    # fragments here so this committed source file contains no literal secret
    # (which would trip GitHub push protection). The generated temp file holds
    # the full strings so scan_secrets has realistic patterns to detect.
    aws_key = "AKIA" + "IOSFODNN7" + "EXAMPLE"
    aws_secret = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"
    stripe = "sk_" + "live_" + "4eC39HqLyjWDarjtT1zdp7dc" + "00000000"
    gh_token = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"
    db_url = "postgres://" + "admin:hunter2@db.internal:5432/prod"
    with open(os.path.join(d, "src", "config.js"), "w") as f:
        f.write(
            '// Demo config — these credentials are FAKE, planted for the demo\n'
            'const config = {\n'
            f'  awsAccessKey: "{aws_key}",\n'
            f'  awsSecret: "{aws_secret}",\n'
            f'  stripeKey: "{stripe}",\n'
            f'  githubToken: "{gh_token}",\n'
            f'  dbUrl: "{db_url}",\n'
            '};\n'
            'module.exports = config;\n'
        )
    return d


SAMPLE = make_sample_app()

# ANSI colors
DIM = "\033[2m"
BOLD = "\033[1m"
CYAN = "\033[36m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
RESET = "\033[0m"


def local_cidr():
    """Best-effort local /24 from the primary interface; falls back to a common default."""
    import socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ".".join(ip.split(".")[:3]) + ".0/24"
    except Exception:
        return "192.168.1.0/24"


def type_out(text, delay=0.012):
    for ch in text:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(delay)
    print()


def run_tool(proc, call_id, name, arguments):
    req = {
        "jsonrpc": "2.0",
        "id": call_id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }
    proc.stdin.write(json.dumps(req) + "\n")
    proc.stdin.flush()
    # Read until we get the response with this id
    while True:
        line = proc.stdout.readline()
        if not line:
            return "(no response)"
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("id") == call_id and "result" in msg:
            content = msg["result"].get("content", [])
            return "\n".join(c.get("text", "") for c in content if c.get("type") == "text")


def banner():
    print(f"{CYAN}{BOLD}")
    print("  ███╗   ███╗ ██████╗██████╗       ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ")
    print("  ████╗ ████║██╔════╝██╔══██╗     ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗")
    print("  ██╔████╔██║██║     ██████╔╝     ██║  ███╗██║   ██║███████║██████╔╝██║  ██║")
    print("  ██║╚██╔╝██║██║     ██╔═══╝      ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║")
    print("  ██║ ╚═╝ ██║╚██████╗██║          ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝")
    print("  ╚═╝     ╚═╝ ╚═════╝╚═╝           ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ")
    print(f"{RESET}")
    print(f"  {DIM}23 security tools for Claude Code & Cursor — 12 need real hardware{RESET}")
    print()
    time.sleep(0.8)


def section(title, sub):
    print()
    print(f"{YELLOW}{BOLD}── {title} ──{RESET}")
    type_out(f"{DIM}{sub}{RESET}", delay=0.008)
    time.sleep(0.4)


def main():
    proc = subprocess.Popen(
        [BINARY],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1,
    )

    # MCP handshake
    init = {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                   "clientInfo": {"name": "demo", "version": "1.0"}},
    }
    proc.stdin.write(json.dumps(init) + "\n")
    proc.stdin.flush()
    proc.stdout.readline()  # init response
    proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
    proc.stdin.flush()

    os.system("clear")
    banner()

    section("sys_info", "$ what machine am I on?  (reads local hardware — no cloud can)")
    print(run_tool(proc, 10, "sys_info", {}))
    time.sleep(2.2)

    section("scan_secrets", f"$ scan_secrets {SAMPLE}  (hardcoded credentials in source)")
    print(run_tool(proc, 11, "scan_secrets", {"path": SAMPLE}))
    time.sleep(2.5)

    section("persistence_scan", "$ persistence_scan  (malware autostart: LaunchAgents, cron, shell profiles)")
    out = run_tool(proc, 12, "persistence_scan", {})
    # Trim to first ~24 lines for screen real estate
    lines = out.splitlines()
    print("\n".join(lines[:24]))
    if len(lines) > 24:
        print(f"{DIM}  ... {len(lines) - 24} more entries{RESET}")
    time.sleep(2.5)

    section("arp_scan", f"$ arp_scan {local_cidr()}  (Layer 2 LAN discovery — every device, even ICMP-silent ones)")
    out = run_tool(proc, 13, "arp_scan", {"cidr": local_cidr()})
    print("\n".join(out.splitlines()[:14]))
    time.sleep(2.4)

    print()
    print(f"{GREEN}{BOLD}  npx -y @zent7x/mcp-guard{RESET}")
    print(f"  {DIM}github.com/zent7x/mcp-guard — 23 tools, one config line, no API key{RESET}")
    print()

    proc.stdin.close()
    proc.terminate()


if __name__ == "__main__":
    main()
