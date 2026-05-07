"""
SafeNet Ghana - Vulnerability Scanner Module
Module 1: Automated Vulnerability Scanner
Author: Patrick Idan
Project: SafeNet Ghana Final Year Project - GCTU Cybersecurity
"""

import nmap
import json
import datetime
import socket
import sys
from typing import Optional


# ─────────────────────────────────────────────
#  SEVERITY SCORING
#  Maps open ports to a risk level.
#  You'll expand this later with CVE lookups.
# ─────────────────────────────────────────────
PORT_RISK = {
    21:   ("FTP",             "HIGH",   "Unencrypted file transfer. Often exploited."),
    22:   ("SSH",             "MEDIUM", "Secure shell. Safe if patched, risky if weak password."),
    23:   ("Telnet",          "CRITICAL","Sends passwords in plaintext. Should never be open."),
    25:   ("SMTP",            "MEDIUM", "Mail server. Can be abused for spam relaying."),
    53:   ("DNS",             "MEDIUM", "DNS resolver. Can be abused for amplification attacks."),
    80:   ("HTTP",            "MEDIUM", "Unencrypted web server. Upgrade to HTTPS."),
    110:  ("POP3",            "HIGH",   "Unencrypted email. Credentials sent in plaintext."),
    135:  ("MS-RPC",          "HIGH",   "Windows RPC. Frequently targeted by malware."),
    139:  ("NetBIOS",         "HIGH",   "Old Windows sharing. Common attack vector."),
    143:  ("IMAP",            "HIGH",   "Unencrypted email access."),
    443:  ("HTTPS",           "LOW",    "Encrypted web. Safe if certificate is valid."),
    445:  ("SMB",             "CRITICAL","Windows file sharing. EternalBlue/WannaCry vector."),
    1433: ("MS SQL Server",   "HIGH",   "Database port. Should never be public-facing."),
    3306: ("MySQL",           "HIGH",   "Database port. Should never be public-facing."),
    3389: ("RDP",             "CRITICAL","Remote Desktop. Brute-force target. Restrict access."),
    5432: ("PostgreSQL",      "HIGH",   "Database port. Should not be publicly exposed."),
    5900: ("VNC",             "HIGH",   "Remote desktop. Often has weak/no authentication."),
    6379: ("Redis",           "CRITICAL","Often runs with no authentication. Critical exposure."),
    8080: ("HTTP Alt",        "MEDIUM", "Alternative web port. Check if intentional."),
    8443: ("HTTPS Alt",       "LOW",    "Alternative HTTPS port."),
    27017:("MongoDB",         "CRITICAL","Database. Historically misconfigured with no auth."),
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def resolve_target(target: str) -> Optional[str]:
    """
    Tries to resolve a hostname to an IP address.
    Returns None if resolution fails.
    """
    try:
        ip = socket.gethostbyname(target)
        print(f"  [+] Resolved '{target}' → {ip}")
        return ip
    except socket.gaierror:
        print(f"  [-] Could not resolve hostname: {target}")
        return None


def run_scan(target: str, scan_type: str = "basic") -> dict:
    """
    Core scanning function. Runs nmap against the target.

    scan_type options:
      "basic"    → Fast scan, top 1000 ports (good for demos)
      "full"     → All 65535 ports (slow but thorough)
      "stealth"  → SYN scan, harder to detect (requires admin/root)
      "version"  → Detects software versions on open ports
    """
    nm = nmap.PortScanner()

    scan_args = {
        "basic":   "-sV --open -T4 --top-ports 100",
        "full":    "-sV --open -T3 -p-",
        "stealth": "-sS --open -T2 --top-ports 100",
        "version": "-sV -sC --open -T4 --top-ports 100",
    }

    args = scan_args.get(scan_type, scan_args["basic"])

    print(f"\n  [*] Starting {scan_type.upper()} scan on: {target}")
    print(f"  [*] Nmap arguments: {args}")
    print(f"  [*] This may take 30–120 seconds...\n")

    try:
        nm.scan(hosts=target, arguments=args)
    except nmap.PortScannerError as e:
        print(f"  [!] Nmap error: {e}")
        print("  [!] Make sure nmap is installed and in your PATH.")
        sys.exit(1)

    return nm


def analyze_results(nm: nmap.PortScanner, target: str) -> dict:
    """
    Parses nmap results and builds a structured vulnerability report.
    This is what eventually becomes your JSON report and dashboard data.
    """
    report = {
        "scan_metadata": {
            "target":    target,
            "timestamp": datetime.datetime.now().isoformat(),
            "tool":      "SafeNet Ghana - Vulnerability Scanner v0.1",
            "author":    "Patrick Idan - GCTU Cybersecurity",
        },
        "hosts": [],
        "summary": {
            "total_hosts":    0,
            "open_ports":     0,
            "critical_count": 0,
            "high_count":     0,
            "medium_count":   0,
            "low_count":      0,
            "overall_risk":   "UNKNOWN",
        }
    }

    for host in nm.all_hosts():
        host_data = {
            "ip":         host,
            "hostname":   nm[host].hostname() or "Unknown",
            "state":      nm[host].state(),
            "open_ports": [],
            "host_risk":  "LOW",
        }

        # Loop through all protocols found (tcp, udp)
        for protocol in nm[host].all_protocols():
            ports = sorted(nm[host][protocol].keys())

            for port in ports:
                port_info = nm[host][protocol][port]

                if port_info["state"] != "open":
                    continue

                # Look up our risk database
                service_name = port_info.get("name", "unknown")
                product      = port_info.get("product", "")
                version      = port_info.get("version", "")

                if port in PORT_RISK:
                    known_name, severity, description = PORT_RISK[port]
                else:
                    # Unknown open port — flag as INFO for manual review
                    known_name  = service_name
                    severity    = "INFO"
                    description = "Unknown service. Review manually."

                port_entry = {
                    "port":        port,
                    "protocol":    protocol,
                    "state":       port_info["state"],
                    "service":     known_name,
                    "product":     f"{product} {version}".strip(),
                    "severity":    severity,
                    "description": description,
                }

                host_data["open_ports"].append(port_entry)
                report["summary"]["open_ports"] += 1

                # Update counters
                if severity == "CRITICAL":
                    report["summary"]["critical_count"] += 1
                elif severity == "HIGH":
                    report["summary"]["high_count"] += 1
                elif severity == "MEDIUM":
                    report["summary"]["medium_count"] += 1
                elif severity == "LOW":
                    report["summary"]["low_count"] += 1

        # Sort ports by severity (worst first)
        host_data["open_ports"].sort(
            key=lambda x: SEVERITY_ORDER.get(x["severity"], 99)
        )

        # Set host risk level to its worst finding
        if host_data["open_ports"]:
            host_data["host_risk"] = host_data["open_ports"][0]["severity"]

        report["hosts"].append(host_data)
        report["summary"]["total_hosts"] += 1

    # Overall risk = worst single finding
    if report["summary"]["critical_count"] > 0:
        report["summary"]["overall_risk"] = "CRITICAL"
    elif report["summary"]["high_count"] > 0:
        report["summary"]["overall_risk"] = "HIGH"
    elif report["summary"]["medium_count"] > 0:
        report["summary"]["overall_risk"] = "MEDIUM"
    elif report["summary"]["low_count"] > 0:
        report["summary"]["overall_risk"] = "LOW"
    else:
        report["summary"]["overall_risk"] = "CLEAN"

    return report


def print_report(report: dict):
    """
    Prints a clean, colour-coded terminal report.
    Later this data feeds your React dashboard and Flutter app.
    """
    COLORS = {
        "CRITICAL": "\033[91m",  # Red
        "HIGH":     "\033[33m",  # Yellow
        "MEDIUM":   "\033[93m",  # Light yellow
        "LOW":      "\033[92m",  # Green
        "INFO":     "\033[94m",  # Blue
        "RESET":    "\033[0m",
        "BOLD":     "\033[1m",
        "CLEAN":    "\033[92m",
    }

    print("\n" + "═" * 60)
    print(f"  {COLORS['BOLD']}SafeNet Ghana — Scan Report{COLORS['RESET']}")
    print("═" * 60)
    meta = report["scan_metadata"]
    print(f"  Target    : {meta['target']}")
    print(f"  Scanned   : {meta['timestamp']}")

    summary = report["summary"]
    risk    = summary["overall_risk"]
    color   = COLORS.get(risk, COLORS["RESET"])
    print(f"  Risk Level: {color}{COLORS['BOLD']}{risk}{COLORS['RESET']}")
    print(f"  Hosts Up  : {summary['total_hosts']}")
    print(f"  Open Ports: {summary['open_ports']}")
    print()

    if summary["critical_count"]:
        print(f"  {COLORS['CRITICAL']}● CRITICAL : {summary['critical_count']}{COLORS['RESET']}")
    if summary["high_count"]:
        print(f"  {COLORS['HIGH']}● HIGH     : {summary['high_count']}{COLORS['RESET']}")
    if summary["medium_count"]:
        print(f"  {COLORS['MEDIUM']}● MEDIUM   : {summary['medium_count']}{COLORS['RESET']}")
    if summary["low_count"]:
        print(f"  {COLORS['LOW']}● LOW      : {summary['low_count']}{COLORS['RESET']}")

    for host in report["hosts"]:
        print(f"\n  {'─'*56}")
        print(f"  {COLORS['BOLD']}Host: {host['ip']} ({host['hostname']}){COLORS['RESET']}")
        print(f"  State: {host['state'].upper()}")

        if not host["open_ports"]:
            print(f"  {COLORS['CLEAN']}  No notable open ports found.{COLORS['RESET']}")
            continue

        print(f"\n  {'PORT':<8}{'SERVICE':<20}{'SEVERITY':<12}DESCRIPTION")
        print(f"  {'─'*56}")

        for p in host["open_ports"]:
            sev_color = COLORS.get(p["severity"], COLORS["RESET"])
            product   = f" ({p['product']})" if p["product"] else ""
            print(
                f"  {p['port']:<8}"
                f"{p['service'] + product:<20}"
                f"{sev_color}{p['severity']:<12}{COLORS['RESET']}"
                f"{p['description'][:38]}"
            )

    print("\n" + "═" * 60)
    print(f"  Report saved to → scan_report.json")
    print("═" * 60 + "\n")


def save_report(report: dict, filename: str = "scan_report.json"):
    """
    Saves the full report as JSON.
    This JSON is what your FastAPI backend will serve to the React dashboard.
    """
    with open(filename, "w") as f:
        json.dump(report, f, indent=2)
    print(f"  [+] JSON report saved: {filename}")


# ─────────────────────────────────────────────
#  MAIN — Entry point
# ─────────────────────────────────────────────
if __name__ == "__main__":

    print("""
  ╔══════════════════════════════════════╗
  ║   SafeNet Ghana - Vulnerability      ║
  ║   Scanner v0.1  |  GCTU CyberSec    ║
  ║   Patrick Idan  |  Module 1          ║
  ╚══════════════════════════════════════╝
    """)

    # Get target from user
    target = input("  Enter target IP or hostname: ").strip()

    if not target:
        print("  [!] No target provided. Exiting.")
        sys.exit(1)

    # Resolve hostname if needed
    ip = resolve_target(target)
    if not ip:
        sys.exit(1)

    # Choose scan type
    print("\n  Scan types:")
    print("  [1] basic   - Fast, top 100 ports (recommended for now)")
    print("  [2] version - Detect software versions (slower)")
    print("  [3] full    - All 65535 ports (very slow)")
    choice = input("\n  Choose scan type [1/2/3] (default: 1): ").strip()

    scan_map = {"1": "basic", "2": "version", "3": "full"}
    scan_type = scan_map.get(choice, "basic")

    # Run the scan
    nm     = run_scan(ip, scan_type)
    report = analyze_results(nm, target)

    # Output results
    print_report(report)
    save_report(report)