```bash
┏━━━━━━━┳━━━━━━━┳━━━━━━━┳━━━━━┳━━━━━┳━━━━━━━┳━━━━━━━┳━━━━━━━┳━━━━━━━┳━━━━━━┳━━━━━━━┳━━━━━━┓
┃ File  ┃ Relro ┃ Cana… ┃ NX  ┃ PIE ┃ RPATH ┃ RUNP… ┃ Symb… ┃ FORT… ┃ For… ┃ Fort… ┃ For… ┃
┃       ┃       ┃       ┃     ┃     ┃       ┃       ┃       ┃       ┃      ┃       ┃ Sco… ┃
┡━━━━━━━╇━━━━━━━╇━━━━━━━╇━━━━━╇━━━━━╇━━━━━━━╇━━━━━━━╇━━━━━━━╇━━━━━━━╇━━━━━━╇━━━━━━━╇━━━━━━┩
│ chall │ Full  │  Yes  │ Yes │ Yes │  No   │  No   │  Yes  │  No   │  No  │  No   │  0   │
└───────┴───────┴───────┴─────┴─────┴───────┴───────┴───────┴───────┴──────┴───────┴──────┘
```

<!-- <details>
<summary>By type</summary>
<p>

</p>
</details> -->

# Categories

<details id="shellcode">
<summary>Shellcode</summary>
<p>

| CTF Name | Challenge | Other bug |
| :---: | :---: | :---: |
| [ImaginaryCTF 2022](#imaginaryctf-2022) | bellcode |  |
| [KMACTF 2022](#kmactf-2022) | Duet | `Buffer Overflow` |
| [pwn.tn](#pwn.tn) | orw |  |

</p>
</details>

<details id="integer-overflow">
<summary>Integer Overflow</summary>
<p>

| CTF Name | Challenge | Other bug/technique |
| :---: | :---: | :---: |
| [HCMUS CTF 2022](#hcmus-ctf-2022) | calert | `Integer Overflow` `Ret2libc` |
| [zer0pts CTF 2022](#zer0pts-ctf-2022) | Modern Rome |  |
| [zer0pts CTF 2022](#zer0pts-ctf-2022) | accountant | `ret2libc` |
| [KCSC - Entrance exam](#kcsc-entrance-exam) | get OVER InT |  |

</p>
</details>

<details id="buffer-overflow">
<summary>Buffer Overflow</summary>
<p>

| CTF Name | Challenge | Other bug/technique |
| :---: | :---: | :---: |
| [file_storage](online/pwnable.vn/file-storage) | c (64 bit) | `Ret2Libc` `Out Of Bound` |  |  |
| [Google CTF 2022](#google-ctf-2022) | FixedASLR | `Out-of-bound` `Crypto - LFSR algorithm` |
| [WhiteHat Play 11](#whitehat-play-11) | pwn07-Silence |  |
| [KMACTF 2022](#kmactf-2022) | Two Shot | `Format String` `Ret2libc` |
| [Pragyan CTF 2022](#pragyan-ctf-2022) | Comeback |  |
| [Pragyan CTF 2022](#pragyan-ctf-2022) | Poly-Flow |  |
| [MOCSCTF 2022](#mocsctf-2022) | calc | `Out-of-bound` |
| [KCSC - Entrance exam](#kcsc-entrance-exam) | Make Me Crash |  |
| [KCSC - Entrance exam](#kcsc-entrance-exam) | ret2win |  |
| [KCSC - Entrance exam](#kcsc-entrance-exam) | bof1 |  |
| [pwnable.tw](#pwnable.tw) | Spirited Away |  |
| [pwnable.tw](#pwnable.tw) | Kidding | `Shellcode` |
| [pwnable.tw](#pwnable.tw) | Start | `Shellcode` |
| [pwn.tn](#pwn.tn) | f_two | `Format String` `Integer Overflow` |

</p>
</details>

<details id="uninitialized-variable">
<summary>Uninitialized Variable</summary>
<p>

| CTF Name | Challenge | Other bug/technique |
| :---: | :---: | :---: |
| [pwnable.tw](#pwnable.tw) | apple store (Didn't make writeup) |  |
| [GDGAlgiers CTF 2022](#gdgalgiers-ctf-2022) | XOR | `Ret2Libc` |

</p>
</details>

<details id="format-string">
<summary>Format String</summary>
<p>

| CTF Name | Challenge | Other bug/technique |
| :---: | :---: | :---: |
| [ImaginaryCTF 2022](#imaginaryctf-2022) | rope |  |
| [ImaginaryCTF 2022](#imaginaryctf-2022) | Format String Foolery |  |
| [ImaginaryCTF 2022](#imaginaryctf-2022) | Format String Fun |  |
| [vsCTF 2022](#vsctf-2022) | Private Bank |  |
| [WhiteHat Play 11](#whitehat-play-11) | pwn06-Ez_fmt |  |
| [HCMUS CTF 2022](#hcmus-ctf-2022) | WWW |  |
| [KCSC CTF 2022](#kcsc-ctf-2022) | pwnMe | `Ret2libc` |
| [Pragyan CTF 2022](#pragyan-ctf-2022) | TBBT |  |
| [Pragyan CTF 2022](#pragyan-ctf-2022) | Portal |  |
| [Wanna Game 2022](#wanna-game-2022) | Letwarnup |  |
| [KCSC - Entrance exam](#kcsc-entrance-exam) | Chall |  |
| [pwn.tn](#pwn.tn) | f_one |  |

</p>
</details>

<details id="rop">
<summary>ROP</summary>
<p>

| CTF Name | Challenge | Other bug/technique |
| :---: | :---: | :---: |
| [DiceCTF 2022](#dicectf-2022) | baby-rop | `Use After Free` |

</p>
</details>

<details id="sig-rop">
<summary>Sig-ROP</summary>
<p>

| CTF Name | Challenge | Other bug/technique |
| :---: | :---: | :---: |
| [KCSC CTF 2022](#kcsc-ctf-2022) | start | `Buffer Overflow` |
| [KCSC CTF 2022](#kcsc-ctf-2022) | feedback | `Buffer Overflow` `Integer Overflow` |

</p>
</details>

<details id="blind-rop">
<summary>Blind-ROP</summary>
<p>

| CTF Name | Challenge | Other bug/technique |
| :---: | :---: | :---: |
| [DefCamp CTF 21-22 Online](#defcamp-ctf-21-22-online) | blindsight | `Buffer Overflow` |

</p>
</details>

<details id="off-by-one">
<summary>Off-by-one</summary>
<p>

| CTF Name | Challenge | Other bug/technique |
| :---: | :---: | :---: |
| [Wanna Game 2022](#wanna-game-2022) | Feedback |  |
| [ISITDTU 2019](#isitdtu-2019) | tokenizer |  |

</p>
</details>

<details id="out-of-bound">
<summary>Out-of-bound</summary>
<p>

| CTF Name | Challenge | Other bug/technique |
| :---: | :---: | :---: |
| [KCSC - Entrance exam](#kcsc-entrance-exam) | ArrayUnderFl0w |  |

</p>
</details>

<details id="ret2dlresolve">
<summary>ret2dlresolve</summary>
<p>

| CTF Name | Challenge | Other bug/technique |
| :---: | :---: | :---: |
| [KCSC CTF 2022](#kcsc-ctf-2022) | readOnly | `Buffer Overflow` |
| [TSJ CTF 2022](#tsj-ctf-2022) | bacteria | `Buffer Overflow` |
| [DiceCTF 2022](#dicectf-2022) | dataeater | `Format String` |

</p>
</details>

<details id="attack-hook">
<summary>Attack hook</summary>
<p>

| CTF Name | Challenge | Other bug/technique |
| :---: | :---: | :---: |
| [SVATTT 2019](#svattt-2019) | three_o_three |  |
| [pwnable.tw](#pwnable.tw) | 3x17 |  |

</p>
</details>

<details id="other">
<summary>Other</summary>
<p>

| CTF Name | Challenge | Other bug/technique |
| :---: | :---: | :---: |
| [LITCTF 2022](#litctf-2022) | IntArray |  |
| [KCSC CTF 2022](#kcsc-ctf-2022) | guess2pwn |  |
| [KCSC - Entrance exam](#kcsc-entrance-exam) | guessMe | `Specific Seed Rand` |
| [pwnable.tw](#pwnable.tw) | calc |  |

</p>
</details>

<details id="heap-overflow">
<summary>Heap Overflow</summary>
<p>

| CTF Name | Challenge | Other bug/technique |
| :---: | :---: | :---: |
| [KCSC CTF 2022](#kcsc-ctf-2022) | babyheap | `Use After Free` `Heap Overflow` |
| [MOCSCTF 2022](#mocsctf-2022) | C@ge |  |

</p>
</details>

<details id="heap-tcache-attack">
<summary>Heap - Tcache attack</summary>
<p>

| CTF Name | Challenge | Other bug/technique |
| :---: | :---: | :---: |
| [vsCTF 2022](#vsctf-2022) | EzOrange | `Out-of-bound` |
| [vsCTF 2022](#vsctf-2022) | ForNBack | `Use After Free` |
| [WhiteHat Play 11](#whitehat-play-11) | pwn08-Ruby | `Integer Overflow` `tcache_perthread_struct attack` |
| [Pragyan CTF 2022](#pragyan-ctf-2022) | Database | `Heap Overflow` |
| [MOCSCTF 2022](#mocsctf-2022) | orange | `House of Orange` |
| [Wanna Game 2022](#wanna-game-2022) | note | `Use After Free` |
| [ISITDTU 2019](#isitdtu-2019) | iz_heap_lv1 |  |
| [DefCamp CTF 21-22 Online](#defcamp-ctf-21-22-online) | cache | `Use After Free` `Double Free` |

</p>
</details>

<details id="heap-house-of-force">
<summary>Heap - House of Force </summary>
<p>

| CTF Name | Challenge | Other bug/technique |
| :---: | :---: | :---: |
| [KCSC CTF 2022](#kcsc-ctf-2022) | 5ecretN0te | `Heap Overflow` |
| [Wolverine Security Conference/CTF](#wolverine-security-conference-ctf) | Us3_th3_F0rc3 | `Heap Overflow` |

</p>
</details>

<details id="heap-house-of-roman">
<summary>Heap - House of Roman </summary>
<p>

| CTF Name | Challenge | Other bug/technique |
| :---: | :---: | :---: |
| [pwnable.tw](#pwnable.tw) | Secret Garden | `Use After Free` `Double Free` |

</p>
</details>

<details id="heap-house-of-botcake">
<summary>Heap - House of Botcacke </summary>
<p>

| CTF Name | Challenge | Other bug/technique |
| :---: | :---: | :---: |
| [FooBar CTF 2022](#foobar-ctf-2022) | Death-note | `Use After Free` `Tcache Attack` |

</p>
</details>

<details id="heap-house-of-husk">
<summary>Heap - House of Husk</summary>
<p>

| CTF Name | Challenge | Other bug/technique |
| :---: | :---: | :---: |
| [ImaginaryCTF 2022](#imaginaryctf-2022) | minecraft | `Use After Free` `Format String` |

</p>
</details>

<details id="heap-house-of-muney">
<summary>Heap - House of Muney</summary>
<p>

| CTF Name | Challenge | Other bug/technique |
| :---: | :---: | :---: |

</p>
</details>

<details id="exploitation-of-file">
<summary>Exploitation of FILE</summary>
<p>

| CTF Name | Challenge | Other bug/technique |
| :---: | :---: | :---: |
| [pwnable.tw](#pwnable.tw) | seethefile | `Buffer Overflow` |


</p>
</details>

<details id="kernel-exploit">
<summary>Kernel Exploit</summary>
<p>

| CTF Name | Challenge | Other bug/technique |
| :---: | :---: | :---: |
| [CakeCTF 2022](#cakectf-2022) | welkerme | `Shellcode` |
| [DownUnderCTF - 2022](#downunderctf-2022) | just-in-kernel | `Shellcode` |


</p>
</details>

# CTF events

### 2022

<details id="gdgalgiers-ctf-2022">
<summary>GDGAlgiers CTF 2022</summary>
<p>

| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [XOR](2022/GDGAlgiers-CTF-2022/XOR) | c (64 bit) | `Uninitialized Variable` | `Ret2Libc` |  |

</p>
</details>

<details id="downunderctf-2022">
<summary>DownUnderCTF - 2022</summary>
<p>

| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [just-in-kernel](2022/DownUnder-CTF-2022/just-in-kernel) | kernel |  |  | First post about kernel exploit, should read this after you read welkerme of [CakeCTF 2022](#cakectf-2022) |

</p>
</details>

<details id="ascis-warmup-2022">
<summary>ASCIS WarmUp - 2022</summary>
<p>

| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [DOGE [Forensics]](2022/ASCIS-WarmUp-2022/DOGE) |  |  |  |  |
| [Simple Forensics [Forensics]](2022/ASCIS-WarmUp-2022/Simple-Forensics) |  |  |  |  |

</p>
</details>

<details id="cakectf-2022">
<summary>CakeCTF 2022</summary>
<p>

| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [welkerme](2022/CakeCTF-2022/welkerme) | kernel |  |  | Basic stuff for kernel exploit. Please read the file README.md to have a first approach of it! |

</p>
</details>

<details id="0ctf-tctf-2022">
<summary>0CTF/TCTF 2022</summary>
<p>

| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [BabyHeap 2022](2022/0CTF-2022/BabyHeap-2022) | c (64 bit) | `Heap Overflow` |  | Attack `tls_dtor_list`, set null for guard and setup fake `dtor_list` in `tls_dtor_list` |

</p>
</details>

<details id="kmactf-iii-2022">
<summary>KMACTF III - 2022</summary>
<p>

| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [Secret Machine](2022/KMACTF-III/SecretMachine) | c (64 bit) |  |  |  |
| [Game of KMA](2022/KMACTF-III/GameofKMA) | c (64 bit) | `Out-Of-Bound` |  |  |


</p>
</details>

<details id="litctf-2022">
<summary>LITCTF 2022</summary>
<p>

| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [IntArray](2022/LITCTF/IntArray) | c (64 bit) |  |  |  |


</p>
</details>

<details id="imaginaryctf-2022">
<summary>ImaginaryCTF 2022</summary>
<p>

| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [Format String Foolery](2022/Imaginary-CTF-2022/FormatStringFoolery) | c (64 bit) | `Format String` |  | Change `link_map->l_addr` to another value so when `_dl_fini` is execute, it will take address of `.fini_array + link_map->l_addr` and execute that address |
| [Format String Fun](2022/Imaginary-CTF-2022/FormatStringFun) | c (64 bit) | `Format String` |  | Change `link_map->l_addr` to another value so when `_dl_fini` is execute, it will take address of `.fini_array + link_map->l_addr` and execute that address |
| [bellcode](2022/Imaginary-CTF-2022/bellcode) | c (64 bit) |  | `Shellcode` |  |
| [golf](2022/Imaginary-CTF-2022/golf) | c (64 bit) | `Format String` |  | Use `%*<k>$c` to write the 32-bit address on stack to an address we want |
| [rope](2022/Imaginary-CTF-2022/rope) | c (64 bit) |  | `Shellcode` | Overwrite `_IO_file_jumps + ??` to make puts execute system |
| [pywrite](2022/Imaginary-CTF-2022/pywrite) | python3 |  |  | Read libc address from a @got and modify a @got to system |
| [minecraft](2022/Imaginary-CTF-2022/minecraft) | c (64 bit) | `Use After Free` `Format String` | `House of Husk` |  |

</p>
</details>

<details id="vsctf-2022">
<summary>vsCTF 2022</summary>
<p>

| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [Private Bank](2022/vsCTF-2022/PrivateBank) | c (64 bit) |  |  |  |
| [ForNBack](2022/vsCTF-2022/ForNBack) | c (64 bit) | `Use After Free` | `Tcache Attack` |  |
| [Private Bank](2022/vsCTF-2022/EzOrange) | c (64 bit) | `Out-Of-Bound` | `Tcache Attack` |  |


</p>
</details>

<details id="google-ctf-2022">
<summary>Google CTF 2022</summary>
<p>

| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [FixedASLR](2022/Google-CTF-2022/FixedASLR) | c (64 bit) | `Buffer Overflow` `Out Of Bound` | `ROPchain` | ASLR is created by `rand(12)` whose algorithm is LFSR. Hence, recover seed (canary) with 6 leaked result of `rand(12)` by using z3, a framework of python |

</p>
</details>

<details id="whitehat-play-11">
<summary>WhiteHat Play 11</summary>
<p>

| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [pwn06-Ez_fmt](2022/WhiteHat-Play-11/pwn06-Ez_fmt) | c (64 bit) | `Format String` |  | `%n` and `%p` (or `%s`) can be used at the same time just in case `%n` in clear form and `%p` (or `%s`) can be in short form. Ex: `%c%c%n%3$p` |
| [pwn07-Silence](2022/WhiteHat-Play-11/pwn07-Silence) | c (64 bit) | `Buffer Overflow` |  | Due to the close of stdout and stderr, we can send data via stdin so we will use `getdents` syscall to get file name and print the flag through stdin; </br> Or we can `dup2()` to reopen stdout and stderr, and get shell; </br> Or just get the shell as normal but without anything to be printed. And when we get the shell, type `exec 1>&0` and everything from stdout will be redirected to stdin. Hence, we get a normal shell. |
| [pwn08-Ruby](2022/WhiteHat-Play-11/pwn08-Ruby) | c (64 bit) | `Integer Overflow` |  | Attacking tcache_perthread_struct by freeing fake chunk which has size of `0x10000` and this size is inside tcache_perthread_struct |


</p>
</details>

<details id="kmactf-2022">
<summary>KMACTF 2022</summary>
<p>

| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [Duet](2022/KMACTF-2022/Duet) | c (64 bit) | `Buffer Overflow` | `Shellcode` | Shellcode (32 bit) can be executed on 64 bit binary and argument when execute `int 0x80` will be eax, ebx, ecx, edx... |
| [Two Shot](2022/KMACTF-2022/TwoShot) | c (64 bit) | `Buffer Overflow` `Format String` | `Ret2libc` |  |


</p>
</details>

<details id="hcmus-ctf-2022">
<summary>HCMUS CTF 2022</summary>
<p>

### Quals
| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [PrintMe](2022/HCMUS-CTF-2022/Quals/PrintMe) |  |  |  |  |
| [Timehash - rev](2022/HCMUS-CTF-2022/Quals/Timehash) | c (64 bit) |  |  | Patch file |
| [WWW](2022/HCMUS-CTF-2022/Quals/WWW) | c (64 bit) | `Format String` | `Overwrite GOT` |  |

### Final
| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [calert](2022/HCMUS-CTF-2022/Final/calert) | c (64 bit) | `Integer Overflow` `Buffer Overflow` | `Ret2libc` | We can change original canary if we know its address which is not in range of libc nor ld |

</p>
</details>

<details id="kcsc-ctf-2022">
<summary>KCSC CTF 2022</summary>
<p>

| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [readOnly](2022/KCSC-CTF-2022/readOnly) | c (64 bit) | `Buffer Overflow` | `Ret2dlresolve` |  |
| [start](2022/KCSC-CTF-2022/start) | c (64 bit) | `Buffer Overflow` | `SROP` |  |
| [feedback](2022/KCSC-CTF-2022/feedback) | c (64 bit) | `Integer Overflow` `Buffer Overflow` | `SROP` |  |
| [guess2pwn](2022/KCSC-CTF-2022/guess2pwn) | c++ (64 bit) |  |  | First byte from `urandom` may be null |
| [pwnMe](2022/KCSC-CTF-2022/pwnMe) | c (64 bit) | `Format String` | `Ret2libc` |  |
| [babyheap](2022/KCSC-CTF-2022/babyheap) | c (64 bit) | `Use After Free` `Heap Overflow` |  |  |
| [5ecretN0te](2022/KCSC-CTF-2022/5ecretN0te) | c (64 bit) | `Heap Overflow` | `House of Force` |  |

</p>
</details>

<details id="wolverine-security-conference-ctf">
<summary>Wolverine Security Conference/CTF</summary>
<p>

| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [Us3_th3_F0rc3](2022/Wolverine-Security-Conference-CTF/Us3_th3_F0rc3) | c (64 bit) | `Heap Overflow` | `House of Force` |  |

</p>
</details>

<details id="zer0pts-ctf-2022">
<summary>zer0pts CTF 2022</summary>
<p>

| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [Modern Rome](2022/zer0pts-CTF-2022/Modern-Rome) | c++ (64 bit) | `Integer Overflow` |  |  |
| [accountant](2022/zer0pts-CTF-2022/accountant) | c (64 bit) | `Integer Overflow` | `ret2libc` | If register (rax, rbx, rcx...) contain `0x10000000000000000` (9 bytes in total), the most significant byte will be remove (the 0x1 will be remove) and make register to null again |

</p>
</details>

<details id="foobar-ctf-2022">
<summary>FooBar CTF 2022</summary>
<p>

| Name | Type | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: | :---: |
| [Death-note](2022/FooBar-CTF-2022/Death-note) | pwn | c (64 bit) | `Use After Free` | `Tcache Attack` `House of Botcake` | Tcache forward pointer changed in libc 2.32 ([source](https://elixir.bootlin.com/glibc/glibc-2.32/source/malloc/malloc.c#L2928)) |

</p>
</details>

<details id="pragyan-ctf-2022">
<summary>Pragyan CTF 2022</summary>
<p>

| Name | Type | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: | :---: |
| [Poly-Flow](2022/Pragyan-CTF-2022/PolyFlow) | pwn | c (32 bit) | `Buffer Overflow` |  |  |
| [Portal](2022/Pragyan-CTF-2022/Portal) | pwn | c (64 bit) | `Format String` |  |  |
| [Database](2022/Pragyan-CTF-2022/database) | pwn | c (64 bit) | `Heap Overflow` | `Tcache Attack` |  |
| [Comeback](2022/Pragyan-CTF-2022/comeback) | pwn | c (32 bit) | `Buffer Overflow` |  |  |
| [TBBT](2022/Pragyan-CTF-2022/TBBT) | pwn | c (32 bit) | `Format String` | `Overwrite GOT` |  |

</p>
</details>

<details id="tsj-ctf-2022">
<summary>TSJ CTF 2022</summary>
<p>

| Name | Type | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: | :---: |
| [bacteria](2022/TSJ-CTF-2022/bacteria) | pwn | c (64 bit) | `Buffer Overflow` | `Ret2dlresolve` | r_offset can be any writable and controllable place, don't need to be @got |

</p>
</details>

<details id="mocsctf-2022">
<summary>MOCSCTF 2022</summary>
<p>

| Name | Type | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: | :---: |
| [C@ge](2022/MOCSCTF-2022/C@ge) | pwn | c++ (64 bit) | `Heap Overflow` | `Tcache Attack` `Ret2libc` | Use libc environ() to leak stack address |
| [calc](2022/MOCSCTF-2022/calc) | pwn | c (64 bit) | `Buffer Overflow` `Unchecked Index` | `ret2win` |  |
| [orange](2022/MOCSCTF-2022/orange) | pwn | c (64 bit) | `Heap Overflow` | `House of Orange` `Tcache Attack` `Unsorted Bin Attack` | Overwrite malloc hook with realloc and realloc hook with one gadget |

</p>
</details>

<details id="wanna-game-2022">
<summary>Wanna Game 2022</summary>
<p>

| Name | Type | File Type | Technique |
| :---: | :---: | :---: | :---: |
| [Letwarnup](2022/wannaGame/letwarnup) | pwn | c (64 bit) | `Format String` `Overwrite GOT` |
| [Feedback](2022/wannaGame/feedback) | pwn | c (64 bit) | `Least Significant Byte` |
| [note](2022/wannaGame/note) | pwn | c (64 bit) | `Heap Attack` `Unsorted Bin Attack` |

</p>
</details>

<details id="kcsc-entrance-exam">
<summary>KCSC - Entrance exam</summary>
<p>

| Name | Type | File Type | Technique |
| :---: | :---: | :---: | :---: |
| [ArrayUnderFl0w](2022/KCSC-CTF-entrance-test/ArrayUnderFl0w) | pwn | c | `Unchecked Index` |
| [guessMe](2022/KCSC-CTF-entrance-test/guessMe) | pwn | c | `Specific Seed Rand` |
| [Make Me Crash](2022/KCSC-CTF-entrance-test/Make-Me-Crash) | pwn | c | `Buffer Overflow` |
| [Chall](2022/KCSC-CTF-entrance-test/Chall) | pwn | c | `Format String` |
| [ret2win](2022/KCSC-CTF-entrance-test/ret2win) | pwn | c | `Buffer Overflow` |
| [get OVER InT](2022/KCSC-CTF-entrance-test/GET_OVER_InT) | pwn | c | `Integer Overflow` |
| [bof1](2022/KCSC-CTF-entrance-test/bof1) | pwn | c | `Buffer Overflow` |

</p>
</details>

<details id="dicectf-2022">
<summary>DiceCTF 2022</summary>
<p>

| Name | Type | File Type | Technique |
| :---: | :---: | :---: | :---: |
| [baby-rop](2022/DiceCTF-2022/baby-rop) | pwn | c (64 bit) | `Heap Attack` `ROP chaining` |
| [dataeater](2022/DiceCTF-2022/dataeater) | pwn | c (64 bit) | `ret2dlresolve` `Fake link_map` |

</p>
</details>

<details id="defcamp-ctf-21-22-online">
<summary>DefCamp CTF 21-22 Online</summary>
<p>

| Name | Type | File Type | Technique |
| :---: | :---: | :---: | :---: |
| [cache](2022/DefCamp-CTF-2022/cache) | pwn | c (64 bit) | `Use After Free` `Double Free` `Tcache Attack` `Overwrite GOT` |
| [blindsight](2022/DefCamp-CTF-2022/blindsight) | pwn | c (64 bit) | `Blind ROP` `Buffer Overflow` |

</p>
</details>



### 2020

### 2019

<details id="isitdtu-2019">
<summary>ISITDTU 2019</summary>
<p>

| Name | Type | File Type | Technique |
| :---: | :---: | :---: | :---: |
| [tokenizer](2019/ISITDTU/tokenizer) | pwn | cpp (64 bit) | `Least Significant Byte` |
| [iz_heap_lv1](2019/ISITDTU/iz_heap_lv1) | pwn | c (64 bit) | `Heap Attack` `Tcache attack` |

</p>
</details>

<details id="svattt-2019">
<summary>SVATTT 2019</summary>
<p>

| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [three_o_three](2019/SVATTT2019/three_o_three) | c (64 bit) | `Unlimited malloc size` | `FILE structure attack` | Malloc with size larger than heap size make the chunk near libc ; `Scanf` flow: `__uflow` -> `_IO_file_underflow` -> `read` 1 byte until meet `\n`; </br> Or we can overwrite exit hook with one gadget. More information can be found [here](https://blog.csdn.net/A951860555/article/details/121581338) |

</p>
</details>

### Online

<details id="pwnable.vn">
<summary>pwnable.vn</summary>
<p>

| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [file_storage](online/pwnable.vn/file-storage) | c (64 bit) | `Ret2Libc` `Out Of Bound` |  |  |

</p>
</details>

<details id="pwnable.tw">
<summary>pwnable.tw</summary>
<p>

| Name | File Type | Bug | Technique | Note |
| :---: | :---: | :---: | :---: | :---: |
| [Start](online/pwnable.tw/Start) | c (32 bit) | `Buffer Overflow` | `ROPchain` `Shellcode` |  |
| [orw](online/pwnable.tw/orw) | c (32 bit) |  | `Shellcode` |  |
| [calc](online/pwnable.tw/calc) | c (32 bit) |  | `ROPchain` |  |
| [3x17](online/pwnable.tw/3x17) | c (64 bit) |  | `ROPchain` | Attack by overwriting `.fini_array` |
| [Re-alloc](online/pwnable.tw/Re-alloc) | c (64 bit) | `Use After Free` | `Overwrite GOT` |  |
| [Kidding](online/pwnable.tw/Kidding) | c (32 bit) | `Buffer Overflow` | `Shellcode` | SYS_SOCKET and SYS_CONNECT to make a reverse shell |
| [seethefile](online/pwnable.tw/seethefile) | c (32 bit) | `Buffer Overflow` |  |  |
| [Spirited Away](online/pwnable.tw/Spirited_Away) | c (32 bit) | `Buffer Overflow` |  |  |
| [Secret Garden](online/pwnable.tw/SecretGarden) | c (64 bit) | `Use After Free` `Double Free` |  |  |

</p>
</details>

<details id="pwn.tn">
<summary>pwn.tn</summary>
<p>

| Name | Type | File Type | Technique |
| :---: | :---: | :---: | :---: |
| [f_one](online/pwn.tn/f_one) | pwn | c (64 bit) | `Format String` `Overwrite GOT` |
| [f_two](online/pwn.tn/f_two) | pwn | c (32 bit) | `Buffer Overflow` `Integer Overflow` `Format String` |

</p>
</details>