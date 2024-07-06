#!/usr/bin/env python3
from sys import argv

from pwn import *

host = "127.0.0.1"
port = 1337
elf = ELF("./binary")

# context.arch = 'amd64'
context.terminal = ['mate-terminal', '-x', 'sh', '-c']
context.log_level = 'info'


def main(mode: str):
    if mode == "local":
        p = elf.process()
        g = gdb.attach(p, gdbscript='''''')
    elif mode == "remote":
        p = connect(host, port)
    else:
        Error("Usage: python3 exploit.py [local|remote]")
        exit(1)

    p.interactive()


if __name__ == "__main__":
    main(argv[1])

# Good luck by @akiidjk
