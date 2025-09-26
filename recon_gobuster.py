#!/usr/bin/env python3
import os, sys, subprocess, requests
from datetime import datetime

if len(sys.argv) != 2:
    print("Usage: recon_gobuster.py <target-ip-or-host>")
    sys.exit(1)

target = sys.argv[1]
outdir = f"recon_{target}_{datetime.now():%Y%m%d_%H%M%S}"
os.makedirs(outdir, exist_ok=True)

# Fetch homepage
for proto in ("http://", "https://"):
    url = proto + target
    try:
        print(f"[*] fetching {url}")
        r = requests.get(url, timeout=8, allow_redirects=True)
        filename = os.path.join(outdir, "homepage_" + proto.strip(":/") + ".html")
        with open(filename, "wb") as f:
            f.write(r.content)
    except Exception as e:
        print(f"[!] {url} failed: {e}")

# Gobuster scan
WORDLIST = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"  # standard Kali wordlist
if not os.path.exists(WORDLIST):
    print(f"[!] Wordlist not found at {WORDLIST}, install dirbuster wordlists first.")
    sys.exit(1)

for proto in ("http://", "https://"):
    url = proto + target
    gobuster_out = os.path.join(outdir, f"gobuster_{proto.strip(':/')}.txt")
    print(f"[*] Running gobuster on {url}")
    try:
        subprocess.run([
            "gobuster", "dir", "-u", url, "-w", WORDLIST, "-o", gobuster_out, "-q"
        ], check=True)
    except Exception as e:
        print(f"[!] Gobuster failed: {e}")

print(f"[*] Done. All outputs saved in {outdir}")
