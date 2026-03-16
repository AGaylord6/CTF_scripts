#!/usr/bin/env python3
'''
Template for pwntools exploits

io.clean()
fit/flat creates nested data structs. fills intermediate data with cyclic patterns. takes dict of {offset: value} pairs

Flags:

LOCAL:      Run a local binary for testing
REMOTE:     ncat to remote host
EXE:        Path to local executable
NOASLR:     ASLR disabled for all created processes
GDB:        GDB will be attached to the created process
ROP:        Search for ROP gadgets in the binary and print them (doesn't run the exploit)
DOCKER:     Run the exploit within the provided docker container (for testing)
DEBUG:      Set log level to debug (default is info)
'''

from pwn import *
import struct

# --- configuration ---
EXECUTABLE = args.EXE or "example_binary"
REMOTE_HOST = args.HOST or 'example.com'
REMOTE_PORT = int(args.PORT or 2222)
context.log_level = "debug"   # "info", "error", or "debug"
DOCKER_IMAGE = "image_name:latest"
USERNAME = "example_name" # for docker
# ----------------------

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or EXECUTABLE, checksec=True)
context.terminal = ["tmux", "splitw", "-h"]


def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    log.info(f"Starting local binary: {args.local}")
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Execute the target binary on the remote host'''
    log.info(f"Connecting to {REMOTE_HOST}:{REMOTE_PORT}")
    # Create TCP/UDP socket connection (like ncat)
    # Can set ssl=True if needed
    return remote(REMOTE_HOST, REMOTE_PORT)

    # For remote ssh server (so you can pass args):
    shell = None
    if not args.LOCAL:
        shell = ssh(user, host, port, password)
        shell.set_working_directory(symlink=True)
    if args.GDB:
        return gdb.debug([remote_path] + argv, gdbscript=gdbscript, ssh=shell, *a, **kw)
    else:
        return shell.process([remote_path] + argv, *a, **kw)

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.DOCKER:
        return process([
            'docker',
            'run',
            '--rm',
            '-u',
            USERNAME,
            '-it',
            DOCKER_IMAGE,
            '/bin/bash'
        ] + argv, *a, **kw, stdin=PTY)
    elif args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

gdbscript = '''
set disassembly-flavor intel
tbreak *0x{exe.entry:x}
continue
'''.format(**locals())
# b *0x402004

# ---------- example exploit flow ----------
def exploit():
    # Pass command-line args: start([str(0x1234)])
    io = start()

    if args.DOCKER:
        # start executable if we're within docker container
        io.send(b"cd ~\n")
        io.send(f"./{exe.filename}\n".encode())

    # payload = b"HELLO" + b"\x00\x01" + b"A"*4 + p64(0x4142434445464748)
    # io.send_bytes(payload)
    # io.sendlineafter("Enter your birthdate (mm/dd/yyyy): ", b'1/1/1')
    # print(io.recvline())

    # asm(shellcraft.execve("/bin/sh", 0, 0))
    # asm(shellcraft.sh())
    # asm(shellcraft.cat("flag.txt"))

    # io.recv(timeout=3)
    # io.recvuntil(b"\n", timeout=3)
    # io.recvn(n, timeout=3)

    # libc = ELF("libc.so.6") or = context.binary.libc
    # print(hex(libc.symbols['stdout']))
    # print(hex(libc.search(b'/bin/sh').__next__()))

    # print(hex(exe.plt['puts'])) or exe.got['puts']

    io.interactive()


def main():
    if args.ROP:
        rop = ROP(EXECUTABLE)
        for r, k in rop.gadgets.items():
            print(r, k)

        # binsh = rop.search(int.from_bytes(b'/bin/sh\x00', 'little'))
        # rop.execve(p64(0x400ab2), 0, 0)

        # print()
        # ret = rop.find_gadget(["ret"])
        # # ret = p64(rop.find_gadget(["ret"][0]))
        # print(ret)

        # once we've added things (huh?)
        print(rop.dump())
        print()
        print(hexdump(bytes(rop)))
        return

    exploit()

if __name__ == "__main__":
    main()
