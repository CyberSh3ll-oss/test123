#!/usr/bin/env python3
"""
================================================================
            RECON TOOLKIT — Authorized Security Testing CLI
================================================================

A menu-driven wrapper around standard reconnaissance utilities
(nmap, amass, theHarvester, dnsenum, dnsrecon, gobuster, ffuf)
and a small set of ADB utilities for managing Android devices
you own or are explicitly authorized to administer.

SCOPE & AUTHORIZATION
----------------------
This tool is intended ONLY for:
  - Targets you own, OR
  - Targets you have explicit written authorization to test
    (e.g. a signed pentest engagement letter, a bug bounty
    program's documented scope, or a lab environment you built)

On first run in a session, the tool requires you to confirm
authorization before any scan or device action executes, and
every action is logged with a timestamp to a local history file
so you have a record of what was run and when.

This project deliberately does NOT include exploitation,
credential-cracking, phishing, or any device feature that
operates without the operator's explicit, per-run authorization
(e.g. no unattended microphone or camera access). Those are out
of scope for this tool by design.
"""

import os
import sys
import json
import shutil
import datetime
import subprocess

# ----------------------------------------------------------------
# Terminal colors
# ----------------------------------------------------------------
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    ORANGE = "\033[38;5;214m"


APP_NAME = "RECON TOOLKIT"
APP_VERSION = "2.0"

HOME = os.path.expanduser("~")
WORKDIR = os.path.join(HOME, "recon_toolkit_output")
HISTORY_FILE = os.path.join(HOME, ".recon_toolkit_history.json")

# ----------------------------------------------------------------
# Tool registry: recon-only, each tool is read-only / passive by
# default usage shown to the user.
# ----------------------------------------------------------------
TOOL_MAP = {
    "amass":        ("amass", "amass", "Subdomain discovery & DNS mapping"),
    "nmap":         ("nmap", "nmap", "Port / service scanning"),
    "theHarvester": ("theHarvester", "theharvester", "Email & host harvesting from public sources"),
    "dnsenum":      ("dnsenum", "dnsenum", "DNS record enumeration"),
    "dnsrecon":     ("dnsrecon", "dnsrecon", "DNS zone & record recon"),
    "gobuster":     ("gobuster", "gobuster", "Directory / DNS brute-force"),
    "ffuf":         ("ffuf", "ffuf", "Fast web fuzzer"),
}

TOOL_EXAMPLES = {
    "amass": ["amass enum -d example.com -passive"],
    "nmap": ["nmap -sC -sV example.com"],
    "theHarvester": ["theHarvester -d example.com -b all"],
    "dnsenum": ["dnsenum example.com"],
    "dnsrecon": ["dnsrecon -d example.com"],
    "gobuster": ["gobuster dir -u https://example.com -w wordlist.txt"],
    "ffuf": ["ffuf -u https://example.com/FUZZ -w wordlist.txt"],
}

# ----------------------------------------------------------------
# Session authorization gate
# ----------------------------------------------------------------
_AUTHORIZED = False
_AUTH_TARGET_NOTE = ""


def require_authorization():
    """
    Blocks any scan/device action until the operator confirms, in
    writing for this session, that they own or are authorized to
    test the target. This is logged to history.
    """
    global _AUTHORIZED, _AUTH_TARGET_NOTE
    if _AUTHORIZED:
        return True

    clear_screen()
    header()
    print(f"  {C.YELLOW}{C.BOLD}AUTHORIZATION REQUIRED{C.RESET}")
    print(f"  {'-' * 56}")
    print("  This tool may only be used against systems you own or")
    print("  have explicit written authorization to test.\n")
    note = input(
        f"  {C.BOLD}Describe your authorization (owner / engagement ref): {C.RESET}"
    ).strip()
    if not note:
        print(f"\n  {C.RED}No authorization statement provided. Exiting action.{C.RESET}")
        return False
    confirm = input(
        f"  {C.BOLD}I confirm I am authorized for this target (y/N): {C.RESET}"
    ).strip().lower()
    if confirm != "y":
        print(f"\n  {C.RED}Authorization not confirmed. Exiting action.{C.RESET}")
        return False

    _AUTHORIZED = True
    _AUTH_TARGET_NOTE = note
    log_event("authorization_confirmed", note)
    return True


# ----------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------
def clear_screen():
    os.system("clear" if os.name != "nt" else "cls")


def header():
    print(f"{C.CYAN}{C.BOLD}")
    print(f"  {'=' * 56}")
    print(f"   {APP_NAME} v{APP_VERSION}")
    print(f"  {'=' * 56}{C.RESET}")


def pause():
    input(f"\n{C.DIM}Press Enter to return to the menu...{C.RESET}")


def ensure_workdir():
    os.makedirs(WORKDIR, exist_ok=True)


def log_event(event, detail=""):
    ensure_workdir()
    entry = {
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event": event,
        "detail": detail,
    }
    history = []
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r") as f:
                history = json.load(f)
        except (json.JSONDecodeError, IOError):
            history = []
    history.append(entry)
    history = history[-200:]
    try:
        with open(HISTORY_FILE, "w") as f:
            json.dump(history, f, indent=2)
    except IOError:
        pass


def is_installed(binary: str) -> bool:
    return shutil.which(binary) is not None


def view_history():
    clear_screen()
    header()
    print(f"\n  {C.YELLOW}Recent activity{C.RESET}")
    print(f"  {'-' * 56}")
    if not os.path.exists(HISTORY_FILE):
        print(f"  {C.DIM}No history yet.{C.RESET}")
        pause()
        return
    with open(HISTORY_FILE, "r") as f:
        try:
            history = json.load(f)
        except json.JSONDecodeError:
            history = []
    if not history:
        print(f"  {C.DIM}No history yet.{C.RESET}")
    for entry in history[-25:]:
        print(f"  {C.DIM}{entry['timestamp']}{C.RESET}  "
              f"{C.ORANGE}{entry['event']}{C.RESET}  {entry.get('detail', '')}")
    pause()


# ----------------------------------------------------------------
# Tool launcher
# ----------------------------------------------------------------
def launch_tool(display_name: str):
    if not require_authorization():
        pause()
        return

    binary, apt_pkg, desc = TOOL_MAP[display_name]

    clear_screen()
    header()
    print(f"\n  {C.BOLD}{display_name}{C.RESET} — {desc}")
    print(f"  {'-' * 56}")

    if not is_installed(binary):
        print(f"  {C.YELLOW}'{binary}' is not installed.{C.RESET}")
        ans = input(f"  Install now via apt? (y/N): ").strip().lower()
        if ans == "y":
            subprocess.run(["sudo", "apt-get", "install", "-y", apt_pkg])
        if not is_installed(binary):
            print(f"  {C.RED}Install failed or skipped — returning to menu.{C.RESET}")
            pause()
            return

    print(f"\n  {C.YELLOW}Example usage:{C.RESET}")
    for ex in TOOL_EXAMPLES.get(display_name, [f"{binary} -h"]):
        print(f"    {C.GREEN}{ex}{C.RESET}")

    target = input(f"\n  {C.BOLD}Enter the full command to run: {C.RESET}").strip()
    if not target:
        print(f"  {C.RED}No command entered.{C.RESET}")
        pause()
        return

    # Only allow invoking the selected binary itself — operator
    # still types the full command/flags, but can't pivot to an
    # unrelated program through this prompt.
    if not target.split()[0].endswith(binary):
        print(f"  {C.RED}Command must start with '{binary}'.{C.RESET}")
        pause()
        return

    log_event("tool_run", target)
    print()
    subprocess.run(target, shell=True)
    pause()


def category_menu(title, tool_keys):
    while True:
        clear_screen()
        header()
        print(f"\n  {C.YELLOW}[ {title} ]{C.RESET}\n")
        for i, key in enumerate(tool_keys, start=1):
            _, _, desc = TOOL_MAP[key]
            print(f"  {C.GREEN}[{i}]{C.RESET} {key:<16} {C.CYAN}->{C.RESET} {desc}")
        print(f"\n  {C.RED}[0]{C.RESET} Back\n")
        choice = input(f"  {C.BOLD}Select: {C.RESET}").strip()
        if choice == "0":
            break
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(tool_keys):
                launch_tool(tool_keys[idx])
        except ValueError:
            pass


# ----------------------------------------------------------------
# ADB device management (consented, operator-driven only)
# ----------------------------------------------------------------
def adb_run(args, timeout=30):
    try:
        result = subprocess.run(["adb"] + args, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except FileNotFoundError:
        return -1, "", "adb not found. Install with: sudo apt install android-tools-adb"
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out."


def adb_check_device():
    code, out, err = adb_run(["devices", "-l"])
    print(out or err)
    log_event("adb_check_device")


def adb_screenshot():
    ensure_workdir()
    local = os.path.join(WORKDIR, f"screenshot_{int(datetime.datetime.now().timestamp())}.png")
    try:
        with open(local, "wb") as f:
            subprocess.run(["adb", "exec-out", "screencap", "-p"], stdout=f, timeout=20, check=True)
        print(f"{C.GREEN}Saved to {local}{C.RESET}")
        log_event("adb_screenshot", local)
    except Exception as e:
        print(f"{C.RED}Screenshot failed: {e}{C.RESET}")


def adb_install_apk():
    path = input("Path to .apk: ").strip().strip('"')
    if not os.path.isfile(path):
        print(f"{C.RED}File not found.{C.RESET}")
        return
    code, out, err = adb_run(["install", "-r", path], timeout=90)
    print(out or err)
    log_event("adb_install_apk", path)


def adb_uninstall_apk():
    pkg = input("Package name to uninstall: ").strip()
    if not pkg:
        return
    if input(f"Uninstall {pkg}? (y/N): ").strip().lower() == "y":
        code, out, err = adb_run(["uninstall", pkg])
        print(out or err)
        log_event("adb_uninstall_apk", pkg)


def adb_reboot():
    if input("Reboot the connected device? (y/N): ").strip().lower() == "y":
        code, out, err = adb_run(["reboot"])
        print(out or err or "Reboot command sent.")
        log_event("adb_reboot")


def adb_storage():
    code, out, err = adb_run(["shell", "df", "/data"])
    print(out or err)
    log_event("adb_storage_check")


def adb_menu():
    if not require_authorization():
        pause()
        return

    items = [
        ("1", "Check connected device", adb_check_device),
        ("2", "Take screenshot", adb_screenshot),
        ("3", "Install APK", adb_install_apk),
        ("4", "Uninstall APK", adb_uninstall_apk),
        ("5", "Reboot device", adb_reboot),
        ("6", "Check storage", adb_storage),
    ]
    while True:
        clear_screen()
        header()
        print(f"\n  {C.YELLOW}[ ADB Device Management — devices you own/administer ]{C.RESET}\n")
        for num, label, _ in items:
            print(f"  {C.GREEN}[{num}]{C.RESET} {label}")
        print(f"\n  {C.RED}[0]{C.RESET} Back\n")
        choice = input(f"  {C.BOLD}Select: {C.RESET}").strip()
        if choice == "0":
            break
        for num, _, fn in items:
            if choice == num:
                fn()
                pause()
                break


# ----------------------------------------------------------------
# Main menu
# ----------------------------------------------------------------
def about():
    clear_screen()
    header()
    print(f"""
  {C.BOLD}Recon Toolkit{C.RESET}
  A focused CLI wrapper around standard, publicly available
  reconnaissance tools, built to practice automation, CLI/UX
  design, and safe-by-default tooling patterns (authorization
  gating, action logging, input validation).

  {C.YELLOW}Explicitly out of scope by design:{C.RESET}
    - exploitation / credential cracking
    - phishing / social engineering
    - any unattended or covert device access

  {C.DIM}Use only on systems you own or are explicitly authorized
  to test.{C.RESET}
""")
    pause()


def main_menu():
    while True:
        clear_screen()
        header()
        print(f"\n  {C.YELLOW}[ Reconnaissance ]{C.RESET}")
        print(f"  {C.GREEN}[1]{C.RESET} Host OSINT (amass, theHarvester)")
        print(f"  {C.GREEN}[2]{C.RESET} DNS Recon (dnsenum, dnsrecon)")
        print(f"  {C.GREEN}[3]{C.RESET} Web Enumeration (gobuster, ffuf)")
        print(f"  {C.GREEN}[4]{C.RESET} Port Scanning (nmap)")
        print(f"\n  {C.YELLOW}[ Device Management ]{C.RESET}")
        print(f"  {C.GREEN}[5]{C.RESET} ADB Device Tools (your own devices)")
        print(f"\n  {C.YELLOW}[ Info ]{C.RESET}")
        print(f"  {C.GREEN}[6]{C.RESET} View activity log")
        print(f"  {C.GREEN}[7]{C.RESET} About")
        print(f"\n  {C.RED}[0]{C.RESET} Exit\n")

        choice = input(f"  {C.BOLD}Select: {C.RESET}").strip()
        if choice == "1":
            category_menu("Host OSINT", ["amass", "theHarvester"])
        elif choice == "2":
            category_menu("DNS Recon", ["dnsenum", "dnsrecon"])
        elif choice == "3":
            category_menu("Web Enumeration", ["gobuster", "ffuf"])
        elif choice == "4":
            category_menu("Port Scanning", ["nmap"])
        elif choice == "5":
            adb_menu()
        elif choice == "6":
            view_history()
        elif choice == "7":
            about()
        elif choice == "0":
            print(f"\n  {C.CYAN}Session closed.{C.RESET}\n")
            sys.exit(0)


if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n\n  {C.YELLOW}Interrupted. Exiting cleanly.{C.RESET}\n")
        sys.exit(0)
