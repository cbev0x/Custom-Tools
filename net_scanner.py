#!/usr/bin/env python3
"""
My Network Port Scanner
Scans TCP and UDP ports on a target host and will attempt to identify protocols in use.
It uses only the Python standard library, no dependencies required.
"""

import socket
import argparse
import concurrent.futures
from datetime import datetime

PORT_PROTOCOLS = {
    20: "FTP Data", 21: "FTP Control", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP Server", 68: "DHCP Client",
    69: "TFTP", 80: "HTTP", 110: "POP3", 111: "RPC", 119: "NNTP",
    123: "NTP", 135: "MS RPC", 137: "NetBIOS Name", 138: "NetBIOS Datagram",
    139: "NetBIOS Session", 143: "IMAP", 161: "SNMP", 162: "SNMP Trap",
    194: "IRC", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    500: "IKE/IPSec", 514: "Syslog", 515: "LPD/LPR", 520: "RIP",
    587: "SMTP Submission", 631: "IPP", 636: "LDAPS", 993: "IMAPS",
    995: "POP3S", 1080: "SOCKS Proxy", 1194: "OpenVPN", 1433: "MSSQL",
    1521: "Oracle DB", 1723: "PPTP", 2049: "NFS", 2082: "cPanel",
    2083: "cPanel SSL", 2086: "WHM", 2087: "WHM SSL", 3306: "MySQL",
    3389: "RDP", 3690: "SVN", 4444: "Metasploit", 5432: "PostgreSQL",
    5900: "VNC", 5901: "VNC-1", 6379: "Redis", 6881: "BitTorrent",
    8080: "HTTP Alt", 8443: "HTTPS Alt", 8888: "HTTP Dev",
    9200: "Elasticsearch", 27017: "MongoDB",
}

TIMEOUT = 1.0

# Returns the application protocol name for each given port
def get_protocol_name(port: int) -> str:
    return PORT_PROTOCOLS.get(port, "Unknown")


# Attempt a TCP connection to host:port and returns protocol if open.
def scan_tcp_port(host: str, port: int) -> dict | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            result = s.connect_ex((host, port))
            if result == 0:
                # Try to grab the banner
                banner = ""
                try:
                    s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s.recv(1024).decode(errors="replace").strip().splitlines()[0]
                except Exception:
                    pass
                return {
                    "port": port,
                    "type": "TCP",
                    "protocol": get_protocol_name(port),
                    "banner": banner,
                }
    except Exception:
        pass
    return None


# Sends a UDP probe to host:port, returns Open/filtered if no ICMP port-unreachable is recieved
def scan_udp_port(host: str, port: int) -> dict | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(TIMEOUT)
            s.sendto(b"\x00" * 8, (host, port))
            try:
                s.recvfrom(1024)
                return {
                    "port": port,
                    "type": "UDP",
                    "protocol": get_protocol_name(port),
                    "banner": "",
                }
            except socket.timeout:
                return {
                    "port": port,
                    "type": "UDP",
                    "protocol": get_protocol_name(port),
                    "banner": "(open|filtered — no response)",
                }
    except Exception:
        pass
    return None


#Will parse a port argument (eg. 22,80,443 or a range like 1-1024) into a list
def parse_ports(port_arg: str) -> list[int]:
    ports = []
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def print_results(results: list[dict], scan_type: str) -> None:
    filtered = [r for r in results if r and r["type"] == scan_type]
    if not filtered:
        print(f"  No open {scan_type} ports found.")
        return

    print(f"  {'PORT':<8} {'PROTOCOL':<22} {'BANNER / NOTE'}")
    print(f"  {'-'*8} {'-'*22} {'-'*40}")
    for r in sorted(filtered, key=lambda x: x["port"]):
        banner = r["banner"][:60] if r["banner"] else ""
        print(f"  {r['port']:<8} {r['protocol']:<22} {banner}")


def scan(host: str, ports: list[int], tcp: bool, udp: bool, workers: int) -> None:
    start_time = datetime.now()
    print(f"\n{'='*60}")
    print(f"  Network Port Scanner")
    print(f"  Target  : {host}")
    print(f"  Ports   : {ports[0]}–{ports[-1]}  ({len(ports)} total)")
    print(f"  Modes   : {'TCP ' if tcp else ''}{'UDP' if udp else ''}")
    print(f"  Started : {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    all_results = []

    if tcp:
        print("[*] Scanning TCP ports ...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(scan_tcp_port, host, p): p for p in ports}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    all_results.append(result)
        print(f"\n  TCP Results:")
        print_results(all_results, "TCP")

    if udp:
        print("\n[*] Scanning UDP ports (this may take a while) ...")
        udp_results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(scan_udp_port, host, p): p for p in ports}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    udp_results.append(result)
                    all_results.append(result)
        print(f"\n  UDP Results:")
        print_results(udp_results, "UDP")

    elapsed = (datetime.now() - start_time).total_seconds()
    print(f"\n{'='*60}")
    print(f"  Scan complete in {elapsed:.2f}s  |  {len(all_results)} open/filtered port(s) found.")
    print(f"{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Network Port Scanner — detect open TCP/UDP ports and protocols",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("host", help="Target IP address or hostname")
    parser.add_argument(
        "-p", "--ports",
        default="1-1024",
        help="Ports to scan. Examples:\n  -p 22,80,443\n  -p 1-65535\n  (default: 1-1024)",
    )
    parser.add_argument("--tcp", action="store_true", default=False, help="Scan TCP ports")
    parser.add_argument("--udp", action="store_true", default=False, help="Scan UDP ports")
    parser.add_argument(
        "-w", "--workers",
        type=int, default=100,
        help="Number of concurrent threads (default: 100)",
    )

    args = parser.parse_args()

    # Defaults to TCP if no protocol is specified
    if not args.tcp and not args.udp:
        args.tcp = True
        args.udp = True

    # Tries to resolve a hostname
    try:
        resolved = socket.gethostbyname(args.host)
        if resolved != args.host:
            print(f"[+] Resolved {args.host} → {resolved}")
        host = resolved
    except socket.gaierror as e:
        print(f"[!] Cannot resolve '{args.host}': {e}")
        return

    ports = parse_ports(args.ports)
    scan(host, ports, args.tcp, args.udp, args.workers)


if __name__ == "__main__":
    main()
