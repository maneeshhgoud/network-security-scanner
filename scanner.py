import socket
import json
import threading
from datetime import datetime
from report_generator import generate_html_report

# ─── Common Ports and Services ───────────────────────────────────────
COMMON_SERVICES = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    135:  "RPC",
    139:  "NetBIOS",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    993:  "IMAPS",
    995:  "POP3S",
    1433: "MSSQL",
    1521: "Oracle DB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017:"MongoDB",
}

# ─── Risk Rating Per Port ────────────────────────────────────────────
HIGH_RISK   = {21, 23, 135, 139, 445, 1433, 3306, 3389, 5900, 6379, 27017}
MEDIUM_RISK = {22, 25, 53, 110, 143, 1521, 5432, 8080, 9200}

def risk_rating(port):
    if port in HIGH_RISK:   return "HIGH"
    if port in MEDIUM_RISK: return "MEDIUM"
    return "LOW"

# ─── Host Discovery ──────────────────────────────────────────────────
def is_host_online(host, timeout=2):
    try:
        socket.setdefaulttimeout(timeout)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, 80))
        return True
    except:
        pass
    try:
        socket.gethostbyname(host)
        return True
    except:
        return False

# ─── Banner Grabbing ─────────────────────────────────────────────────
def grab_banner(host, port, timeout=2):
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((host, port))
        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = s.recv(1024).decode(errors="ignore").strip()
        s.close()
        lines = [l for l in banner.splitlines() if l.strip()]
        return lines[0][:60] if lines else "Connected"
    except:
        return "N/A"

# ─── Single Port Scanner ─────────────────────────────────────────────
def scan_port(host, port, open_ports, lock):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((host, port))
        s.close()
        if result == 0:
            service = COMMON_SERVICES.get(port, "Unknown")
            banner  = grab_banner(host, port)
            risk    = risk_rating(port)
            with lock:
                open_ports.append({
                    "port":    port,
                    "service": service,
                    "risk":    risk,
                    "banner":  banner,
                })
    except:
        pass

# ─── Threaded Port Scanner ───────────────────────────────────────────
def scan_ports(host, port_range):
    open_ports = []
    lock       = threading.Lock()
    threads    = []

    print(f"\n  Scanning ports {port_range[0]} to {port_range[1]}...")
    print(f"  Please wait — this may take 1-2 minutes...\n")

    for port in range(port_range[0], port_range[1] + 1):
        t = threading.Thread(
            target=scan_port,
            args=(host, port, open_ports, lock)
        )
        threads.append(t)
        t.start()
        if len(threads) % 100 == 0:
            for t in threads:
                t.join()
            threads = []

    for t in threads:
        t.join()

    return sorted(open_ports, key=lambda x: x["port"])

# ─── OS Fingerprinting ───────────────────────────────────────────────
def fingerprint_os(open_ports):
    port_nums = [p["port"] for p in open_ports]
    if 3389 in port_nums:               return "Windows (RDP detected)"
    if 22 in port_nums and \
       445 not in port_nums:            return "Linux / Unix (SSH, no SMB)"
    if 445 in port_nums and \
       139 in port_nums:                return "Windows (SMB/NetBIOS detected)"
    if 548 in port_nums:                return "macOS (AFP detected)"
    if open_ports:                      return "Unknown OS"
    return "Could not determine"

# ─── Console Report ──────────────────────────────────────────────────
def print_report(host, open_ports, scan_time, os_guess):
    print("\n" + "=" * 57)
    print("        NETWORK SECURITY SCANNER")
    print("        Professional Penetration Testing Tool")
    print("=" * 57)
    print(f"  Target     : {host}")
    print(f"  Scan Time  : {scan_time}")
    print(f"  OS Guess   : {os_guess}")
    print(f"  Open Ports : {len(open_ports)}")
    print("=" * 57)

    if not open_ports:
        print("\n  [OK] No open ports found in scanned range.\n")
        return

    print("\n[PORT SCAN RESULTS]\n")
    print(f"  {'Port':<7} {'Service':<16} {'Risk':<8} Banner")
    print(f"  {'─'*7} {'─'*16} {'─'*8} {'─'*30}")

    for p in open_ports:
        print(f"  {p['port']:<7} {p['service']:<16} {p['risk']:<8} {p['banner']}")

    print("\n[RISK SUMMARY]")
    high   = sum(1 for p in open_ports if p["risk"] == "HIGH")
    medium = sum(1 for p in open_ports if p["risk"] == "MEDIUM")
    low    = sum(1 for p in open_ports if p["risk"] == "LOW")
    print(f"  HIGH   : {high} port(s)  ← Immediate attention required")
    print(f"  MEDIUM : {medium} port(s)  ← Review recommended")
    print(f"  LOW    : {low} port(s)  ← Monitor")

    print("\n[RECOMMENDATIONS]\n")
    for p in open_ports:
        if p["risk"] == "HIGH":
            print(f"  [!] Port {p['port']} ({p['service']}) — "
                  f"HIGH RISK: Restrict access, apply firewall rules immediately.")
        elif p["risk"] == "MEDIUM":
            print(f"  [~] Port {p['port']} ({p['service']}) — "
                  f"MEDIUM RISK: Verify this service is necessary.")

    print("\n" + "=" * 57)

# ─── Main ────────────────────────────────────────────────────────────
def main():
    with open("config.json") as f:
        config = json.load(f)

    all_results = []

    for target in config["targets"]:
        host       = target["host"]
        port_range = target["port_range"]

        print("\n" + "=" * 57)
        print(f"  TARGET: {host}")
        print("=" * 57)

        print(f"\n[HOST DISCOVERY]")
        if is_host_online(host):
            print(f"  [+] {host} is ONLINE — proceeding with scan")
        else:
            print(f"  [-] {host} appears OFFLINE — skipping")
            continue

        scan_time  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        open_ports = scan_ports(host, port_range)
        os_guess   = fingerprint_os(open_ports)

        print_report(host, open_ports, scan_time, os_guess)

        all_results.append({
            "host":       host,
            "scan_time":  scan_time,
            "os_guess":   os_guess,
            "open_ports": open_ports,
        })

    # Save JSON
    with open("report.json", "w") as f:
        json.dump(all_results, f, indent=2)
    print("\n  [+] JSON report saved to report.json")

    # Generate HTML
    generate_html_report(all_results)
    print("  [+] HTML report saved to report.html")
    print("\n  Open report.html in your browser to view the full report!\n")

if __name__ == "__main__":
    main()
