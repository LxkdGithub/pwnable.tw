from pwn import *

p = process("./spirited_away")


def add(name, age, reazon, comment):
    p.sendafter("Please enter your name: ", name)
    p.sendafter("Please enter your age: ", age)
    p.sendafter("Why did you came to see this movie? ", str(age))
    p.sendafter("Please enter your comment: ", comment)



def free():
    p.sendafter("Would you like to leave another comment? <y/n>: ", "y")

add("0", '0', '0', '0')
p.recvuntil("Name: ")
name = p.recvuntil("Age: ")
age = p.recvuntil("Reazon: ")
print(p64())










