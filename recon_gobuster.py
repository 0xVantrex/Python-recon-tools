#!/usr/bin/env python3


import os
import sys
import subprocess
import requests
import random
import string
from datetime import datetime

# Config
WORDLIST = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
GOBUSTER_TIMEOUT = 300  # seconds for gobuster
REQUEST_TIMEOUT = 8

def mkdir(path):
    try:
        os.makedirs(path, exist_ok=True)
    except Exception as e:
        print(f"[!] Failed to create directory {path}: {e}")
        sys.exit(1)

def ping_check(target):
    print(f"[*] pinging {target}")
    try:
        rc = subprocess.call(["ping", "-c", "2", target], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if rc == 0:
            print(f"[+] {target} is reachable (ping ok)")
        else:
            print(f"[-] ping returned non-zero (target may be down). continuing anyway.")
    except Exception as e:
        print(f"[!] ping failed: {e}")

def run_nmap_quick(target, outdir):
    print("[*] running nmap -sC -sV (quick scan)")
    nmap_outbase = os.path.join(outdir, "nmap_quick")
    try:
        subprocess.run(["nmap", "-sC", "-sV", "-oA", nmap_outbase, target], check=False)
        print(f"[+] nmap outputs saved to {nmap_outbase}.*")
    except Exception as e:
        print(f"[!] nmap run failed: {e}")

def fetch_homepages(target, outdir):
    saved = {}
    for proto in ("http://", "https://"):
        url = proto + target
        try:
            print(f"[*] fetching {url}")
            r = requests.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            fname = os.path.join(outdir, f"homepage_{proto.strip(':/')}.html")
            with open(fname, "wb") as f:
                f.write(r.content)
            saved[proto] = {"url": r.url, "len": len(r.content), "status": r.status_code, "file": fname}
            print(f"[+] saved {url} -> {fname} (status {r.status_code}, len {len(r.content)})")
        except Exception as e:
            print(f"[!] {url} failed: {e}")
    return saved

def random_path():
    return "this-should-not-exist-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=12))

def detects_wildcard(base_url):
    """Return True if server redirects/random-paths land on same page or return similar body length."""
    test_path = "/" + random_path()
    try:
        r = requests.get(base_url + test_path, timeout=REQUEST_TIMEOUT, allow_redirects=True)
    except Exception as e:
        print(f"[!] wildcard detect: request failed for {base_url}{test_path}: {e}")
        return False

    try:
        base = requests.get(base_url + "/", timeout=REQUEST_TIMEOUT, allow_redirects=True)
    except Exception:
        return False

    # Condition A: final landing URL same as base (redirected back)
    if r.url.rstrip("/") == base.url.rstrip("/"):
        return True

    # Condition B: content length nearly identical
    if abs(len(r.content) - len(base.content)) <= 10:
        return True

    return False

def run_gobuster_smart(url, outpath, wordlist=WORDLIST):

    if not os.path.exists(wordlist):
        print(f"[!] Gobuster wordlist not found at {wordlist}. Skipping gobuster for {url}.")
        return False

    print(f"[*] Detecting wildcard behavior for {url} ...")
    use_wildcard = detects_wildcard(url)
    print(f"[*] wildcard detected: {use_wildcard}")

    # Build command using explicit long flags to avoid ambiguous parsing
    cmd = [
        "gobuster", "dir",
        "--url", url,
        "--wordlist", wordlist,
        "--output", outpath,
        "--no-progress"   # roughly equivalent to -q
    ]

    if use_wildcard:
        cmd.append("--wildcard")

    # follow redirects
    cmd.append("--redirect")

    # if HTTPS, skip cert verification
    if url.startswith("https://"):
        cmd.append("--no-tls-validation")

    print(f"[*] Running gobuster: {' '.join(cmd)}")
    try:
        # Let gobuster write directly to outpath (we don't stream stdout here)
        p = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=GOBUSTER_TIMEOUT)
        print(f"[+] Gobuster finished for {url}. Output -> {outpath}")
        return True
    except subprocess.TimeoutExpired:
        print(f"[!] Gobuster timed out for {url}. Increase GOBUSTER_TIMEOUT if needed.")
        return False
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.decode(errors="ignore") if e.stderr else ""
        print(f"[!] Gobuster failed for {url}: exit {e.returncode}.")
        print(f"[!] stderr (first 300 chars):\n{stderr[:300]}")
        return False
    except Exception as e:
        print(f"[!] Gobuster unknown error for {url}: {e}")
        return False

def simple_html_report(outdir, target, saved_homepages):
    rpath = os.path.join(outdir, "report.html")
    print(f"[*] Writing simple HTML report to {rpath}")
    with open(rpath, "w", encoding="utf-8") as f:
        f.write("<html><head><meta charset='utf-8'><title>Recon Report</title></head><body>\n")
        f.write(f"<h1>Recon Report for {target}</h1>\n")
        f.write(f"<p>Timestamp: {datetime.now().isoformat()}</p>\n")
        f.write("<h2>Homepages fetched</h2>\n<ul>\n")
        for proto, info in saved_homepages.items():
            f.write(f"<li>{proto} - final URL: {info['url']} - status: {info['status']} - length: {info['len']} - <a href=\"{os.path.basename(info['file'])}\">view</a></li>\n")
        f.write("</ul>\n")
        f.write("<h2>Files</h2>\n<ul>\n")
        for fname in sorted(os.listdir(outdir)):
            if fname == "report.html":
                continue
            f.write(f"<li><a href=\"{fname}\">{fname}</a></li>\n")
        f.write("</ul>\n</body></html>\n")
    print("[+] report written")

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 recon_suite.py <target-ip-or-host>")
        sys.exit(1)

    target = sys.argv[1]
    outdir = f"recon_{target}_{datetime.now():%Y%m%d_%H%M%S}"
    mkdir(outdir)

    # 1) ping
    ping_check(target)

    # 2) nmap quick
    run_nmap_quick(target, outdir)

    # 3) fetch homepages
    saved = fetch_homepages(target, outdir)

    # 4) smart gobuster runs (http + https)
    http_out = os.path.join(outdir, "gobuster_http.txt")
    run_gobuster_smart("http://" + target, http_out)

    https_out = os.path.join(outdir, "gobuster_https.txt")
    run_gobuster_smart("https://" + target, https_out)

    # 5) write simple HTML report
    simple_html_report(outdir, target, saved)

    print(f"[*] All done. Results in {outdir}")

if __name__ == "__main__":
    main()
