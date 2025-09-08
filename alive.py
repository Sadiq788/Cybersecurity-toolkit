import requests

# Read subdomains list
with open("live.txt", "r") as f:
    subdomains = f.read().splitlines()

alive = []

for sub in subdomains:
    for proto in ["http://", "https://"]:
        url = proto + sub
        try:
            r = requests.get(url, timeout=5, verify=False)
            if r.status_code < 500:  # consider alive
                print(f"[+] Alive: {url} ({r.status_code})")
                alive.append(url)
                break  # no need to test both http/https
        except:
            pass

# Save alive subdomains
with open("alive_subdomains.txt", "w") as f:
    f.write("\n".join(alive))
