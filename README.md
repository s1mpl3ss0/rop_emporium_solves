# ROP Emporium Solves

A repository containing my solves for the [ROP Emporium](https://ropemporium.com) challenges.

## Setup

- [pip](https://github.com/pypa/pip)
- [pip-tools](https://github.com/jazzband/pip-tools)

Run `pip-compile` then `pip-sync` to setup the environment.

## Tools

- [pwninit](https://github.com/io12/pwninit) (optional)
- [pwntools](https://github.com/Gallopsled/pwntools)

## Solves

| Challenge | x86_64 | x86 | ARMv5 | MIPS |
|-|-|-|-|-|
| [ret2win](https://ropemporium.com/challenge/ret2win.html) | [✔️](./1_ret2win/1_ret2win_x64.py) | [✔️](./1_ret2win/1_ret2win_x86.py) | [✔️](./1_ret2win/1_ret2win_armv5.py) | [✔️](./1_ret2win/1_ret2win_mipsel.py) |
| [split](https://ropemporium.com/challenge/split.html) | [✔️](./2_split/2_split_x64.py) | [✔️](./2_split/2_split_x86.py) | [✔️](./2_split/2_split_armv5.py) | ❌ |
| [callme](https://ropemporium.com/challenge/callme.html) | [✔️](./3_callme/3_callme_x64.py) | [✔️](./3_callme/3_callme_x86.py) | [✔️](./3_callme/3_callme_armv5.py) | ❌ |
| [write4](https://ropemporium.com/challenge/write4.html) | [✔️](./4_write4/4_write4_x64.py) | [✔️](./4_write4/4_write4_x86.py) | ❌ | ❌ |
| [badchars](https://ropemporium.com/challenge/badchars.html) | [✔️](./5_badchars/5_badchars_x64.py) | ❌ | ❌ | ❌ |
| [fluff](https://ropemporium.com/challenge/fluff.html) | [✔️](./6_fluff/6_fluff_x64.py) | ❌ | ❌ | ❌ |
| [pivot](https://ropemporium.com/challenge/pivot.html) | [✔️](./7_pivot/7_pivot_x64.py) | ❌ | ❌ | ❌ |
| [ret2csu](https://ropemporium.com/challenge/ret2csu.html) | [✔️](./8_ret2csu/8_ret2csu_x64.py) | ❌ | ❌ | ❌ |
