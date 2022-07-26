### Table of content

- [Categories](#categories)
- [CTF events](#ctf-events)

<!-- <details>
<summary>By type</summary>
<p>

</p>
</details> -->

---

## Categories

## CTF events

<details>
<summary>vsCTF 2022</summary>
<p>

| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [Private Bank](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/vsCTF-2022/PrivateBank) | c (64 bit) |  |  |  |
| [ForNBack](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/vsCTF-2022/ForNBack) | c (64 bit) | `Use After Free` | `Tcache Attack` |  |
| [Private Bank](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/vsCTF-2022/EzOrange) | c (64 bit) | `Out-Of-Bound` | `Tcache Attack` |  |


</p>
</details>

<details>
<summary>Google CTF 2022</summary>
<p>

| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [FixedASLR](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/Google-CTF-2022/FixedASLR) | c (64 bit) | `Buffer Overflow` `Out Of Bound` | `ROPchain` | ASLR is created by `rand(12)` whose algorithm is LFSR. Hence, recover seed (canary) with 6 leaked result of `rand(12)` by using z3, a framework of python |

</p>
</details>

<details>
<summary>WhiteHat Play 11</summary>
<p>

| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [pwn06-Ez_fmt](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/WhiteHat-Play-11/pwn06-Ez_fmt) | c (64 bit) | `Format String` |  | `%n` and `%p` (or `%s`) can be used at the same time just in case `%n` in clear form and `%p` (or `%s`) can be in short form. Ex: `%c%c%n%3$p` |
| [pwn07-Silence](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/WhiteHat-Play-11/pwn07-Silence) | c (64 bit) | `Buffer Overflow` |  | Due to the close of stdout and stderr, we can send data via stdin so we will use `getdents` syscall to get file name and print the flag through stdin; </br> Or we can `dup2()` to reopen stdout and stderr, and get shell; </br> Or just get the shell as normal but without anything to be printed. And when we get the shell, type `exec 1>&0` and everything from stdout will be redirected to stdin. Hence, we get a normal shell. |
| [pwn08-Ruby](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/WhiteHat-Play-11/pwn08-Ruby) | c (64 bit) | `Integer Overflow` |  | Attacking tcache_perthread_struct by freeing fake chunk which has size of `0x10000` and this size is inside tcache_perthread_struct |


</p>
</details>

<details>
<summary>KMACTF 2022</summary>
<p>

| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [Duet](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/KMACTF-2022/Duet) | c (64 bit) | `Buffer Overflow` | `Ret2Shellcode` | Shellcode (32 bit) can be executed on 64 bit binary and argument when execute `int 0x80` will be eax, ebx, ecx, edx... |
| [Two Shot](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/KMACTF-2022/TwoShot) | c (64 bit) | `Buffer Overflow` `Format String` | `Ret2libc` |  |


</p>
</details>

<details>
<summary>HCMUS CTF 2022</summary>
<p>

### Quals
| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [PrintMe](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/HCMUS-CTF-2022/Quals/PrintMe) |  |  |  |  |
| [Timehash - rev](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/HCMUS-CTF-2022/Quals/Timehash) | c (64 bit) |  |  | Patch file |
| [WWW](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/HCMUS-CTF-2022/Quals/WWW) | c (64 bit) | `Format String` | `Overwrite GOT` |  |

### Final
| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [calert](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/HCMUS-CTF-2022/Final/calert) | c (64 bit) | `Integer Overflow` `Buffer Overflow` | `Ret2libc` | We can change original canary if we know its address which is not in range of libc nor ld |

</p>
</details>

<details>
<summary>KCSC CTF 2022</summary>
<p>

| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [readOnly](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/KCSC-CTF-2022/readOnly) | c (64 bit) | `Buffer Overflow` | `Ret2dlresolve` |  |
| [start](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/KCSC-CTF-2022/start) | c (64 bit) | `Buffer Overflow` | `SROP` |  |
| [feedback](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/KCSC-CTF-2022/feedback) | c (64 bit) | `Integer Overflow` `Buffer Overflow` | `SROP` |  |
| [guess2pwn](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/KCSC-CTF-2022/guess2pwn) | c++ (64 bit) |  |  | First byte from `urandom` may be null |
| [pwnMe](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/KCSC-CTF-2022/pwnMe) | c (64 bit) | `Format String` | `Ret2libc` |  |
| [babyheap](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/KCSC-CTF-2022/babyheap) | c (64 bit) | `Use After Free` `Heap Overflow` |  |  |
| [5ecretN0te](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/KCSC-CTF-2022/5ecretN0te) | c (64 bit) | `Heap Overflow` | `House of Force` |  |

</p>
</details>

<details>
<summary>Wolverine Security Conference/CTF</summary>
<p>

| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [Us3_th3_F0rc3](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/Wolverine-Security-Conference-CTF/Us3_th3_F0rc3) | c (64 bit) | `Heap Overflow` | `House of Force` |  |

</p>
</details>

<details>
<summary>zer0pts CTF 2022</summary>
<p>

| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [Modern Rome](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/zer0pts-CTF-2022/Modern-Rome) | c++ (64 bit) | `Integer Overflow` |  |  |
| [accountant](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/zer0pts-CTF-2022/accountant) | c (64 bit) | `Integer Overflow` | `ret2libc` | If register (rax, rbx, rcx...) contain `0x10000000000000000` (9 bytes in total), the most significant byte will be remove (the 0x1 will be remove) and make register to null again |

</p>
</details>

<details>
<summary>FooBar CTF 2022</summary>
<p>

| Name | Type | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: | :---: |
| [Death-note](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/FooBar-CTF-2022/Death-note) | pwn | c (64 bit) | `Use After Free` | `Tcache Attack` `House of Botcake` | Tcache forward pointer changed in libc 2.32 ([source](https://elixir.bootlin.com/glibc/glibc-2.32/source/malloc/malloc.c#L2928)) |

</p>
</details>

<details>
<summary>Pragyan CTF 2022</summary>
<p>

| Name | Type | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: | :---: |
| [Poly-Flow](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/Pragyan-CTF-2022/PolyFlow) | pwn | c (32 bit) | `Buffer Overflow` |  |  |
| [Portal](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/Pragyan-CTF-2022/Portal) | pwn | c (64 bit) | `Format String` |  |  |
| [Database](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/Pragyan-CTF-2022/database) | pwn | c (64 bit) | `Heap Overflow` | `Tcache Attack` |  |
| [Comeback](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/Pragyan-CTF-2022/comeback) | pwn | c (32 bit) | `Buffer Overflow` |  |  |
| [TBBT](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/Pragyan-CTF-2022/TBBT) | pwn | c (32 bit) | `Format String` | `Overwrite GOT` |  |

</p>
</details>

<details>
<summary>TSJ CTF 2022</summary>
<p>

| Name | Type | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: | :---: |
| [bacteria](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/TSJ-CTF-2022/bacteria) | pwn | c (64 bit) | `Buffer Overflow` | `Ret2dlresolve` | r_offset can be any writable and controllable place, don't need to be @got |

</p>
</details>

<details>
<summary>MOCSCTF 2022</summary>
<p>

| Name | Type | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: | :---: |
| [C@ge](https://github.com/nhtri2003gmail/writeup-mocsctf2022.mocsctf.com-Cage) | pwn | c++ (64 bit) | `Heap Overflow` | `Tcache Attack` `Ret2libc` | Use libc environ() to leak stack address |
| [calc](https://github.com/nhtri2003gmail/writeup-mocsctf2022.mocsctf.com-calc) | pwn | c (64 bit) | `Buffer Overflow` `Unchecked Index` | `ret2win` |  |
| [orange](https://github.com/nhtri2003gmail/writeup-mocsctf2022.mocsctf.com-orange) | pwn | c (64 bit) | `Heap Overflow` | `House of Orange` `Tcache Attack` `Unsorted Bin Attack` | Overwrite malloc hook with realloc and realloc hook with one gadget |

</p>
</details>

<details>
<summary>pwnable.tw</summary>
<p>

| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [Start](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/online/pwnable.tw/Start) | c (32 bit) | `Buffer Overflow` | `ROPchain` `Shellcode` |  |
| [orw](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/online/pwnable.tw/orw) | c (32 bit) |  | `Shellcode` |  |
| [calc](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/online/pwnable.tw/calc) | c (32 bit) |  | `ROPchain` |  |
| [3x17](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/online/pwnable.tw/3x17) | c (64 bit) |  | `ROPchain` | Attack by overwriting `.fini_array` |

</p>
</details>

<details>
<summary>Wanna Game 2022</summary>
<p>

| Name | Type | File Type | Technique |
| :---: | :---: | :---: | :---: |
| [Letwarnup](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/wannaGame/letwarnup) | pwn | c (64 bit) | `Format String` `Overwrite GOT` |
| [Feedback](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/wannaGame/feedback) | pwn | c (64 bit) | `Least Significant Byte` |
| [note](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/wannaGame/note) | pwn | c (64 bit) | `Heap Attack` `Unsorted Bin Attack` |

</p>
</details>

<details>
<summary>pwn.tn</summary>
<p>

| Name | Type | File Type | Technique |
| :---: | :---: | :---: | :---: |
| [f_one](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/online/pwn.tn/f_one) | pwn | c (64 bit) | `Format String` `Overwrite GOT` |
| [f_two](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/online/pwn.tn/f_two) | pwn | c (32 bit) | `Buffer Overflow` `Integer Overflow` `Format String` |

</p>
</details>

<details>
<summary>KCSC - Entrance exam</summary>
<p>

| Name | Type | File Type | Technique |
| :---: | :---: | :---: | :---: |
| [ArrayUnderFl0w](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/KCSC-CTF/ArrayUnderFl0w) | pwn | c | `Unchecked Index` |
| [guessMe](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/KCSC-CTF/guessMe) | pwn | c | `Specific Seed Rand` |
| [Make Me Crash](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/KCSC-CTF/Make-Me-Crash) | pwn | c | `Buffer Overflow` |
| [Chall](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/KCSC-CTF/Chall) | pwn | c | `Format String` |
| [ret2win](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/KCSC-CTF/ret2win) | pwn | c | `Buffer Overflow` |
| [get OVER InT](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/KCSC-CTF/GET_OVER_InT) | pwn | c | `Integer Overflow` |
| [bof1](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/KCSC-CTF/bof1) | pwn | c | `Buffer Overflow` |

</p>
</details>

<details>
<summary>ISITDTU 2019</summary>
<p>

| Name | Type | File Type | Technique |
| :---: | :---: | :---: | :---: |
| [tokenizer](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2019/ISITDTU/tokenizer) | pwn | cpp (64 bit) | `Least Significant Byte` |
| [iz_heap_lv1](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2019/ISITDTU/iz_heap_lv1) | pwn | c (64 bit) | `Heap Attack` `Tcache attack` |

</p>
</details>

<details>
<summary>DiceCTF 2022</summary>
<p>

| Name | Type | File Type | Technique |
| :---: | :---: | :---: | :---: |
| [baby-rop](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/DiceCTF-2022/baby-rop) | pwn | c (64 bit) | `Heap Attack` `ROP chaining` |
| [dataeater](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/DiceCTF-2022/dataeater) | pwn | c (64 bit) | `ret2dlresolve` `Fake link_map` |

</p>
</details>

<details>
<summary>DefCamp CTF 21-22 Online</summary>
<p>

| Name | Type | File Type | Technique |
| :---: | :---: | :---: | :---: |
| [cache](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/DefCamp-CTF-2022/cache) | pwn | c (64 bit) | `Use After Free` `Double Free` `Tcache Attack` `Overwrite GOT` |
| [blindsight](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2022/DefCamp-CTF-2022/blindsight) | pwn | c (64 bit) | `Blind ROP` `Buffer Overflow` |

</p>
</details>

<details>
<summary>SVVATTT 2019</summary>
<p>

| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [three_o_three](https://github.com/nhtri2003gmail/CTFNote/tree/master/writeup/2019/SVATTT2019/three_o_three) | c (64 bit) | `Unlimited malloc size` | `FILE structure attack` | Malloc with size larger than heap size make the chunk near libc ; `Scanf` flow: `__uflow` -> `_IO_file_underflow` -> `read` 1 byte until meet `\n`; </br> Or we can overwrite exit hook with one gadget. More information can be found [here](https://blog.csdn.net/A951860555/article/details/121581338) |

</p>
</details>

</p>
</details>