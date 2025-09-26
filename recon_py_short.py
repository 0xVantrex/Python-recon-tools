#!/usr/bin/env python3
# recon_py_short.py — tiny starter: ping -> nmap quick -> fetch homepages
import os, sys, subprocess, datetime, requests

if len(sys.argv) != 2:
    print("Usage: recon_py_short.py <target-ip-or-host>")
    sys.exit(1)

target = sys.argv[1]
outdir = f"recon_{target}_{datetime.datetime.now():%Y%m%d_%H%M%S}"
os.makedirs(outdir, exist_ok=True)

# 1) ping check (just to know if it's up)
print("[*] pinging", target)
rc = subprocess.call(["ping", "-c", "2", target])
if rc != 0:
    print("[-] ping failed (target may be down). continuing anyway.")

# 2) quick nmap (-sC -sV)
print("[*] running nmap -sC -sV (quick scan)")
nmap_out = os.path.join(outdir, "nmap_quick")
subprocess.run(["nmap", "-sC", "-sV", "-oA", nmap_out, target], check=False)

# 3) fetch HTTP/HTTPS homepages (if present)
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

print("[*] done. outputs saved to", outdir)
