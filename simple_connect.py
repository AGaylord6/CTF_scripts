from pwn import *

HOST = "54f24c98e28ebb09.chal.ctf.ae"
io = remote(host=HOST, port=443, ssl=True, sni=HOST)

io.interactive()