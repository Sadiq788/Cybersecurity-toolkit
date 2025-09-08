#!/usr/bin/env python3
import subprocess
import argparse
import ipaddress
import sys
import os
import socket

# --- Validators ---

def validate_target(target):
    """Validate input: IP (v4/v6) or resolvable domain name."""
    try:
        # If it's a valid IP, accept it
        return str(ipaddress.ip_address(target))
    except ValueError:
        try:
            # If it's a domain, check if it resolves
            socket.gethostbyname(target)
            return target
        except socket.gaierror:
            raise argparse.ArgumentTypeError(f"Invalid target (IP/Domain): {target}")

def validate_port(port):
    """Validate single port or port range (1-65535)."""
    if "-" in port:
        try:
            start, end = port.split("-")
            start, end = int(start), int(end)
            if not (0 < start <= 65535 and 0 < end <= 65535 and start <= end):
                raise ValueError
        except ValueError:
            raise argparse.ArgumentTypeError(f"Invalid port range: {port}")
    else:
        try:
            port_int = int(port)
            if not (0 < port_int <= 65535):
                raise ValueError
        except ValueError:
            raise argparse.ArgumentTypeError(f"Invalid port: {port}")
    return port

# --- Main logic ---

def main():
    parser = argparse.ArgumentParser(description="⚡ Legendary Ultimate Nmap Scanner (Domain/IP Supported)")
    parser.add_argument("target", nargs="?", help="Target IP address or domain")
    parser.add_argument("port", nargs="?", help="Port or port range (e.g., 22 or 1-1000)")
    parser.add_argument("-o", "--output", help="Base name for saving output in all formats (-oA)")

    args, unknown = parser.parse_known_args()

    # Ask for target if not provided
    if not args.target:
        args.target = input("Enter target IP or domain: ").strip()
        try:
            args.target = validate_target(args.target)
        except argparse.ArgumentTypeError as e:
            print(f"[-] {e}")
            sys.exit(1)

    # Ask for Port if not provided
    if not args.port:
        args.port = input("Enter port or port range (e.g., 22 or 1-1000): ").strip()
        args.port = validate_port(args.port)

    # --- Ask for scan type interactively ---
    print("\nChoose scan type(s) [multiple allowed, separated by space/comma]:")
    print(" 1) TCP Connect Scan (default)")
    print(" 2) TCP SYN Scan (-sS)")
    print(" 3) TCP ACK Scan (-sA)")
    print(" 4) TCP FIN Scan (-sF)")
    print(" 5) TCP Xmas Scan (-sX)")
    print(" 6) TCP Null Scan (-sN)")
    print(" 7) UDP Scan (-sU)")
    print(" 8) Service Version Detection (-sV)")
    print(" 9) OS Detection (-O)")
    print("10) Aggressive Scan (-A)")
    print("11) Default Scripts (-sC)")
    print("12) No Ping (-Pn)")
    print("13) Ping Scan Only (-sn)")
    print("14) Fast Scan (-F)")
    print("15) Intense Scan (-T4)")
    print("16) Stealth Scan (-sS -T2)")
    choices = input("Enter choice(s) (e.g., 2 7 9): ").replace(",", " ").split()

    # --- Build Nmap command ---
    cmd = ["nmap", "-p", args.port]

    for choice in choices:
        choice = choice.strip()
        if choice == "2":
            cmd.append("-sS")
        elif choice == "3":
            cmd.append("-sA")
        elif choice == "4":
            cmd.append("-sF")
        elif choice == "5":
            cmd.append("-sX")
        elif choice == "6":
            cmd.append("-sN")
        elif choice == "7":
            cmd.append("-sU")
        elif choice == "8":
            cmd.append("-sV")
        elif choice == "9":
            cmd.append("-O")
        elif choice == "10":
            cmd.append("-A")
        elif choice == "11":
            cmd.append("-sC")
        elif choice == "12":
            cmd.append("-Pn")
        elif choice == "13":
            cmd.append("-sn")
        elif choice == "14":
            cmd.append("-F")
        elif choice == "15":
            cmd.append("-T4")
        elif choice == "16":
            cmd.extend(["-sS", "-T2"])
        # "1" = default TCP connect scan → no flag needed

    # --- Firewall/CDN evasion options ---
    print("\nChoose evasion/bypass option(s) [multiple allowed, space/comma separated]:")
    print(" 1) Fragment Packets (-f)")
    print(" 2) Custom MTU (--mtu)")
    print(" 3) Decoy Scan (-D)")
    print(" 4) Spoof Source IP (-S)")
    print(" 5) Fake Source Port (-g)")
    print(" 6) Append Random Data (--data-length)")
    print(" 7) Randomize Host Order (--randomize-hosts)")
    print(" 8) Slow Scan (--scan-delay)")
    print(" 9) IDS Evasion Timing (-T0 or -T1)")
    evasion_choices = input("Enter choice(s) or press Enter to skip: ").replace(",", " ").split()

    for ev in evasion_choices:
        ev = ev.strip()
        if ev == "1":
            cmd.append("-f")
        elif ev == "2":
            mtu = input("Enter MTU size (e.g., 24, 8): ").strip()
            cmd.extend(["--mtu", mtu])
        elif ev == "3":
            decoys = input("Enter decoy IPs (comma separated, e.g., 192.168.1.5,8.8.8.8): ").strip()
            cmd.extend(["-D", decoys])
        elif ev == "4":
            spoof_ip = input("Enter spoofed source IP: ").strip()
            cmd.extend(["-S", spoof_ip])
        elif ev == "5":
            sport = input("Enter fake source port (e.g., 53 for DNS): ").strip()
            cmd.extend(["-g", sport])
        elif ev == "6":
            length = input("Enter extra data length (e.g., 50): ").strip()
            cmd.extend(["--data-length", length])
        elif ev == "7":
            cmd.append("--randomize-hosts")
        elif ev == "8":
            delay = input("Enter scan delay (e.g., 100ms, 1s): ").strip()
            cmd.extend(["--scan-delay", delay])
        elif ev == "9":
            stealth = input("Choose timing (0=Paranoid, 1=Sneaky): ").strip()
            cmd.append(f"-T{stealth}")

    if args.output:
        cmd.extend(["-oA", args.output])  # save in all formats

    cmd.append(args.target)

    print(f"\n[+] Running: {' '.join(cmd)}\n")

    try:
        # Live streaming output
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for line in process.stdout:
            print(line, end="")
        process.wait()

        if process.returncode != 0:
            stderr = process.stderr.read()
            print("[-] Nmap error:\n", stderr)
            sys.exit(process.returncode)

        if args.output:
            print(f"\n[✔] Results saved with base: {args.output}")

    except KeyboardInterrupt:
        print("\n[!] Scan aborted by user.")
        sys.exit(1)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Warning: Some scans may need root (e.g., SYN, UDP, OS detection, spoofing).")
        print("    Try running with sudo.\n")
    main()
