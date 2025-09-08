#!/usr/bin/env python3
import subprocess
import sys

# --- Subdomain enumeration with amass ---
def run_amass(domain):
    print(f"[+] Enumerating subdomains for {domain}...")
    cmd = ["amass", "enum", "-passive", "-d", domain]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]
    except subprocess.CalledProcessError as e:
        print("[-] Amass failed:", e.stderr)
        return []

# --- Alive hosts check with httpx ---
def run_httpx(subdomains):
    print("[+] Checking for alive subdomains...")
    try:
        process = subprocess.Popen(
            ["httpx", "-silent"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True
        )
        out, _ = process.communicate("\n".join(subdomains))
        return [line.strip() for line in out.splitlines() if line.strip()]
    except Exception as e:
        print("[-] Httpx failed:", e)
        return []

# --- Directory fuzzing with ffuf ---
def run_ffuf(url, wordlist="common.txt"):
    print(f"[+] Running ffuf on {url}")
    cmd = [
        "ffuf", "-u", f"{url}/FUZZ",
        "-w", wordlist,
        "-mc", "200,301,302"
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"[-] ffuf failed on {url}: {e.stderr}"

# --- Main workflow ---
if __name__ == "__main__":
    domain = input("Enter target domain: ").strip()

    # 1. Subdomain enumeration
    subdomains = run_amass(domain)
    print(f"[+] Found {len(subdomains)} subdomains")

    if not subdomains:
        sys.exit("[-] No subdomains found. Exiting.")

    # 2. Alive check
    alive = run_httpx(subdomains)
    print(f"[+] Found {len(alive)} alive subdomains")

    # 3. Directory fuzzing
    for host in alive:
        dirs = run_ffuf(host)
        print(f"\n--- Directories for {host} ---\n{dirs}")
