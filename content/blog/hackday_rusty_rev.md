---
author: "frereit"
title: "HackDay 2025 - Rusty Rev Writeup"
date: "2025-01-28"
description: "A short writeup for the \"rusty_rev\" challenge from the HackDay 2025 Qualifications."
tags:
    - "ctf"
toc: false
---

The "rusty_rev" challenge was, as the name suggests, a Rust reverse engineering challenge for the [HackDay 2025 Qualifications CTF](https://hackday.fr/).

## Challenge Description

> Hello agent, a trusted source managed to find one of the most secured app of the black mist crew, but unfortunately, we can't find the password to access it.
> 
> We know your talents for reverse engineering, we need you to help us this password.
>
> Download: [rust_rev](/files/hackday2025/rusty_rev)
> 
> SHA256: `71553d736b4299a40069ff3ae1fbd242b50f88b44c28a49ef559ac34248581d5`

## Dynamic analysis

Running the binary gives us a simple password prompt:

```
$ ./rusty_rev 
Please input your password : LETMEIN 
Wrong password, reporting incident to the admin
```

Running the binary under `ltrace` to see what libc functions are called by the binary:

```
$ ltrace ./rusty_rev 
--- Called exec() ---
Please input your password : gdb error, please reboot the computer
+++ exited (status 0) +++
```

Huh, well, looks like the binary has some anti-debugging techniques built-in. We'll have to keep that in mind.

We can also try to run the binary under `strace`. This will probably run into the same anti-debugging checks, but might reveal something about how they are implemented.

I'll spare you the whole output, but once we execute `strace ./rusty_rev`, we should notice a suspicious `write` call, followed by an `execveat`, so let's just filter down to only those syscalls:

```
$ strace -e trace=write,execveat ./rusty_rev
write(3, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\0\202\0\0\0\0\0\0"..., 391616) = 391616
execveat(3, "", [""], 0x5b92175fbc00 /* 1 var */, AT_EMPTY_PATH) = 0
write(1, "\n\342\226\221\342\226\221\342\226\221\342\226\221\342\226\221\342\226\221\342\226\221\342\226\221\342\226\221\342\226\221\342"..., 1937
░░░░░░░░░░░░░░░░░█████░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░████░░░░░███░░░░░░░░░░░░░░░
░░░░██████████░░░░░░████████████░░░░░░░░
░░░░█░░░░░░░█░░░░████░░░░░░░░░░██░░░░░░░
░░░██░░░░░░██░░░░░█░░░░░░░░░░░██░░░░░░░░
░░░█░░░░░░░█░░░░░░███░░░░░█████░░░░░░░░░
░░░░█░░░░░░█░░░░░░░░░███████░░░░░░░░░░░░
░░░░░███████░░░░░░░░░░░░░░░█░░░░░░░░░░░░
░░░░░░░░░░░█░░░███████░░░░░█░░░░░░░░░░░░
░░░░░░░░░░░█░░░█░░░░░█░░░░░█░░░░░░░░░░░░
░░░░░░░░░░░█░░░█░░░░░█░░░░█░░░░░░░░░░░░░
░░░░░░░░░░░█░░░█░░░░░█░░░░█░░░░░░░░░░░░░
░░░░░░░░░░░█░░░█░░░░░█░░░░█░░░░░░░░░░░░░
░░░░░░░░░░░█░░░█░░░░░██████░░░░░░░░░░░░░
░░░░░░░░░░░█████░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
) = 1937
+++ exited with 0 +++
```

Heh, this time we get an Among Us character instead of the "GDB error". There might be some randomness assosciated with the anti-debugging checks. The first `write` syscall writes to file descriptor `3`, and it looks like the content that is written to the file descriptor is an ELF file. This is then executed with the following `execveat` syscall. This indicates a packed binary within the `rusty_rev` binary, which is decrypted or extracted to memory on startup, and then executed. We can use `strace` again to dump the inner executable:

```
$ strace -e trace=write --write=3 -o inner_elf_dump.txt ./rusty_rev
```

We now have a file `inner_elf_dump.txt` which contains a hexdump of the data written to file descriptor `3`:

```
write(3, "\177ELF\2\1\1\0\0\0\0\0\0\0\0\0\3\0>\0\1\0\0\0\0\202\0\0\0\0\0\0"..., 391616) = 391616
 | 00000  7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00  .ELF............ |
 | 02690  08 00 00 00 00 00 00 00  0a 09 05 00 00 00 00 00  ................ |
....
 | 5f990  00 00 00 00 00 00 00 00  d2 f0 05 00 00 00 00 00  ................ |
 | 5f9a0  29 01 00 00 00 00 00 00  00 00 00 00 00 00 00 00  )............... |
 | 5f9b0  01 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................ |
write(1, "Please input your password : ", 29) = 29
--- SIGINT {si_signo=SIGINT, si_code=SI_KERNEL} ---
+++ killed by SIGINT +++
```

To convert this back to a raw binary, first grep for only lines starting with ` | `, then remove everything except the raw hexdump, and convert it to binary with `xxd`:

```
$ cat inner_elf_dump.txt | grep " | " | cut -c 11- | rev | cut -c 21- | rev | xxd -r -p > inner.elf
$ file inner.elf
inner.elf: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=cc6c625f81896dbe1bfe2028ae14a6948839c031, for GNU/Linux 4.4.0, stripped
```

Great, we extracted the inner binary. Let's see if it still works:

```
$ chmod +x inner.elf
$ ./inner.elf 
Please input your password : 
```

Perfect.

### Anti-debugging

Let's now take a closer look at the anti-debugging technique within the binary. Once again inspecting the `strace` output, we can focus on the `openat` syscall to find a potential anti-debugging technique:

```
$ strace -e trace=openat ./inner.elf 
openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libgcc_s.so.1", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/proc/self/maps", O_RDONLY|O_CLOEXEC) = 3
openat(AT_FDCWD, "/proc/self/status", O_RDONLY|O_CLOEXEC) = 3
Please input your password : gdb error, please reboot the computer
+++ exited with 0 +++
```

The binary seems open "/proc/self/status", which is commonly opened to check for the "TracerPid" line, which is non-zero when a process is tracing the current process:

```
$ cat /proc/self/status | grep TracerPid
TracerPid:      0
$ strace cat /proc/self/status 2>/dev/null | grep Tracer
TracerPid:      45387
```

Look at the `strings` in the inner ELF binary seems to confirm this suspicion:

```
$ strings inner.elf | grep proc/self/status
/proc/self/statusTracerPid:     ST0P175734M3D
```

A simple fix might be to replace the `/proc/self/status` string with some other path with contains the same content as `/proc/self/status`, but with `TracerPid` set to `0`:

We have to take care that the path that we are replacing the string with is the same length, to ensure that there is not any problems with offsets changing:

```
$ cp /proc/self/status /dev/shm/XXstatus
$ sed -i 's/proc\/self\//dev\/shm\/XX/' inner.elf
$ strings inner.elf | grep /dev/shm/XXstatus
/dev/shm/XXstatusTracerPid:     ST0P175734M3D
```

Running the binary under `strace` with this patch applied seems to have bypassed the anti-debugging check, as we know get prompted for the password just like when running the binary outside the debugger, and the `getrandom` syscalls have disappeared from the `strace` output:

```
$ strace -e trace=getrandom ./rusty_rev 
getrandom("\x33\xb4\x9b\xdf\x9c\x8b\x6f\xd8", 8, GRND_NONBLOCK) = 8
getrandom("\x47\xde\x8c\xb6\xe7\xd9\x47\xb9", 8, GRND_NONBLOCK) = 8
getrandom("", 0, 0)                     = 0
getrandom("\x08\xce\xe1\xdb\x73\x39\x1b\x2b\xbb\x61\xc4\x16\x0c\x4e\x51\x7b\x4e\x66\xd7\x55\xea\x89\x2a\x5e\x64\x0c\xab\xd5\x62\xd0\xd5\x65", 32, 0) = 32
$ strace -e trace=getrandom ./inner.elf 
getrandom("\x02\x76\xe3\xf6\x62\xbc\x0f\x4f", 8, GRND_NONBLOCK) = 8
Please input your password : 
```

## Static Analysis

### Rehydrating the binary

We saw in the `file` output of `inner.elf` that the binary is stripped. This is extremely annoying, especially with Rust binaries, where all libraries are statically linked into the final binary.

A great tool for this is [Cerberus](https://github.com/h311d1n3r/Cerberus) by h311d1n3r, which automatically finds libraries used inside the binary, compiles them, and then matches their function signatures against the provided binary.

We can simply build the tool inside Docker, and then use it to rehydrate our binary. Note: I recommend installing Rust "manually" inside the container instead of using Cerberus, because Cerberus will install Rust from the Debian repositories, which are usually not up-to-date.

```
# git clone --recursive https://github.com/h311d1n3r/Cerberus && cd Cerberus
# docker build -f ./docker/ubuntu/Dockerfile-22.04 -t cerberus .
# cd ..
# docker run --rm -it -v "$(pwd):/mnt/data" cerberus:latest /bin/bash
root@cd00b99d9341:/mnt/data# apt install curl
root@cd00b99d9341:/mnt/data# curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
root@cd00b99d9341:/mnt/data# . "$HOME/.cargo/env" 
root@cd00b99d9341:/mnt/data# /root/Cerberus/build/cerberus inner.elf -output inner_resym.elf
---------- Cerberus (v2.0) ----------
[*] Identified package manager: apt
[*] Running as root.
[*] Identified file as UNIX - Executable and Linkable Format (ELF).
[*] Identified language : Rust
[*] Continue analysis with this language ? (Y/n) 
[*] Using Rust for analysis.
[*] The following packages are required :
With apt:
- git
- golang
- python3
- python3-pip
- patch
With pip3:
- pyinstaller
With git:
- radare2
- Goliath
With cargo:
- cross
[*] Proceed to installation ? (Y/n) 
[...]
[*] File was found to be stripped.
[*] Extracting libraries...
[+] Identified 2 libraries.
[*] Here is the current list of libraries :
-------------------------------
1. rand:0.8.5
2. rand_chacha:0.3.1
-------------------------------
1. Validate 2. Add library 3. Change library version 4. Remove library
[*] Your choice ? (1-4) 1
[*] Installing libraries...
[*] Installing rand:0.8.5...
[+] Success !
[*] Installing rand_chacha:0.3.1...
[+] Success !
[+] Installed 2 libraries.
[*] Analyzing target functions...
[+] Analyzed 528 functions.
[*] Matching with functions from libraries...
[+] Matched 324 functions. Matching rate: 61%
[*] Demangling function names...
[+] Done !
[*] Writing output file...
[+] Done !
root@cd00b99d9341:/mnt/data# exit
```

Alright, we now have a "inner_resym.elf" binary which should contain a lot more symbols than the stripped binary that we started out with.

### Decompilation

I'll use Binary Ninja to decompile the rehydrated binary. Here's the `main` function:

```rust
00009020  int32_t main(int32_t argc, char** argv, char** envp)

00009020      struct Elf64_Header* (* rax)()
00009020      struct Elf64_Header* (* var_8)() = rax
0000902e      var_8 = sub_8434
00009046      return sub_26550(&var_8, &data_5d088, sx.q(argc), argv, 0)
```

Just like libc's `__libc_start_main`, `sub_26550` is probably a Rust-internal function responsible for starting the "real" main of the program. So we can safely assume that `sub_8434` is the real main function of the Rust program. This is quickly confirmed when peeking inside:

```rust
00008434  struct Elf64_Header* sub_8434()

00008457      char const (** const var_b8)[0xc0] = 0x1b600000000
0000845a      int32_t var_b0 = 0
00008461      int16_t var_ac = 0
00008467      var_b0.b = 1
0000847f      int32_t var_118
0000847f      std::fs::OpenOptions::_open::h20fd30929551db2c(&var_118, &var_b8, "/dev/shm/XXstatusTracerPid:\tST0…", 0x11)
00008488      char const (** const* rdx_13)[0xc0]
00008488
```

We can see the `open` call at the top of the function, opening the `/dev/shm/XXstatus` file, so this is probably the start of the anti-debugging check we saw in the dynamic analysis section.

To find out where the password is read, let's look for the "Please input your password" string in the binary, and see where it is referenced. The `data_5cfa8` global holds a pointer to the string, and it referenced only once in the real main function:

```rust
00008d47          var_b8 = &s_Please_input_your_password
00008d4a          var_b0.q = 1
00008d52          int64_t var_a8_2 = 8
00008d5e          int128_t var_a0_1 = zx.o(0)
00008d63          std::io::stdio::_print::he9dfbe767523a89e(&var_b8)
00008d69          std::io::stdio::stdout::h48e25a94a6fcffb1()
00008d74          var_118.q = &data_600f0
00008d77          ssize_t rax_21 = _<std::io::stdio::Stderr...:Write>::write_fmt::h9c7d53ac92ac6926(&var_118)
```

Clearly the password prompt is printed to the terminal at this point. Just a few line below this print, we can spot the following code snippet:

```rust
00008db7              rax_22, rdx_10 = sub_28460(&var_118, &var_e0)
00008db7              
00008dbf              if ((rax_22 & 1) != 0)
00008fb0                  var_b8 = rdx_10
00008fd0                  core::result::unwrap_failed::h899ed7ab2ccb8159("Failed to read lineWrong passwor…", 0x13, &var_b8)
00008fd0                  noreturn
```

Looks like `rax_22` somehow contains the `Result` of the readline call. So, even though Cerberus was unable to provide a symbol for the `sub_28460` function, we can assume this function has something to do with reading a line of input from `stdin`. For the next step, we need to know that in Rust, unlike in C, strings are generally wide-pointers. That means they are not just an 8-byte address pointing to the start of the string, but actually contain the length of the string next to the pointer. We'll therefore need to tell Binary Ninja that this variable is actually a 16 byte struct, with two fields. One for the length, and another for the pointer:

```c
struct RustyString
{
    uint64_t length;
    char* data;
};
```

Then apply this type to the `var_118` variable and rename it to `user_input`. Looking at the references for `user_input`, the following snippet should jump out:

```rust
00008e1a              char* data_1 = var_118.data;
00008e25              char const (** const data_6)[0x85];
00008e25              
00008e25              if (var_108_1 != 0x17)
00008e4f                  data_6 = &data_5cfe8;
00008e25              else
00008e25              {
00008e27                  char zmm0_2[0x10] = *(uint128_t*)data_1;
00008e30                  char zmm1_2[0x10] = __pcmpeqb_xmmdq_memdq(*(uint128_t*)(data_1 + 7), (*(uint128_t*)data_4d040));
00008e30                  
00008e4d                  if (_mm_movemask_epi8((__pcmpeqb_xmmdq_memdq(zmm0_2, data_4d050) & zmm1_2)) == 0xffff)
00008ec4                      data_6 = &data_5cff8;
00008e4d                  else
00008e4f                      data_6 = &data_5cfe8;
00008e25              }
```

Ok, so there are some scary SSE instructions in there, but they are actually just checking for equality of two buffers. Firstly, I assume that the check `if (var_108_1 != 0x17)` checks the length of the string. Let's just assume for now that `var_108_1` contains the length of the string we entered. `data_5cfe8` is a pointer to the "Wrong password" string, so we can probably conclude from this check that the password is `0x17 = 23` characters long. If the length check passed, the data is checked for equality with two buffers.

As I said, the SSE instructions look scary, but let's  look at them in the disassembly and then turn them into pseudocode:

```asm
00008e27  f30f6f03           movdqu  xmm0, xmmword [rbx]
00008e2b  f30f6f4b07         movdqu  xmm1, xmmword [rbx+0x7]
00008e30  660f740d08420400   pcmpeqb xmm1, xmmword [rel data_4d040]
00008e38  660f740510420400   pcmpeqb xmm0, xmmword [rel data_4d050]
00008e40  660fdbc1           pand    xmm0, xmm1
00008e44  660fd7c0           pmovmskb eax, xmm0
00008e48  3dffff0000         cmp     eax, 0xffff
00008e4d  7475               je      0x8ec4
```

This is already much more readable than the Pseudo-C in my opinion, but here it is in pseudocode:

```
load_into_xmm0(data);
load_into_xmm1(data + 7):
comparison_one := compare_xmm_with_memory(xmm1, data_4d040);
comparison_two := compare_xmm_with_memory(xmm0, data_4d050);
if all_msb_set(and(comparison_one, comparison_two)) {
    ...
} else {
    ...
}
```

So, in words, `data_4d050` contains 16 bytes which are compared against the last 16 bytes of some data derived from our input, and `data_4d040` is compared against the first 16 bytes of our input. Because we assume our input is only 23 bytes long, this should mean that the last 9 bytes and the first 9 bytes of `data_4d050` and `data_4d040` should be the same, which is indeed the case:

```
0004d040  int128_t data_4d040 = 
0004d040  0f ca 1b 12 65 0f e1 05 22 0f cf 14 36 e8 3c 3a  ....e..."...6.<:
0004d050  int128_t data_4d050 = 
0004d050  a5 e7 f3 3f 8d e1 f5 0f ca 1b 12 65 0f e1 05 22  ...?.......e..."
```

This probably confirms that the password that we should enter is 23 characters long.
Unfortunately, as we can also see, clearly the data being compared against is not just the password, but it is masked or encrypted in some way.

However, a simple strategy is to consider whatever masking or encryption is applied as a set of 23 sboxes, one sbox for each index. This essentially considers the masking as a polyalphabetic substitution cipher, based on individual bytes. Because the masked data is hardcoded in the binary, we can probably assume that the cipher is "static".

## Recovering the SBOXes

With the polyalphabetic substitution cipher assumption, we can just recover all 23 sboxes by first using "AAAAAAAAAAAAAAAAAAAAAAA" as the password, recording what "A" maps to at each index, then using "BBBBBBBBBBBBBBBBBBBBBBB", and so on, until we know what each character is masked to at each index. Once we have the sboxes, we simply invert them and then unmask the hardcoded data to get the password / flag. Let's get to work an implement this with [libdebug](https://github.com/libdebug/libdebug):

```python
from pwn import *
from libdebug import debugger
import numpy as np
import string

candidates = string.ascii_letters + string.digits + string.punctuation

# We have 23 SBOXes, each of which maps len(candidates) to some byte value.
sboxes = np.zeros((23, len(candidates)), dtype=np.uint8)

# Now, for each candidate, we check what it is masked to at each index.
for i, candidate in enumerate(candidates):
    p = process("./inner_resym.elf")
    d = debugger("./inner_resym.elf")
    d.attach(p.proc.pid)
    # We set a breakpoint just after our data was loaded into xmm0/xmm1
    d.breakpoint(0x8e30, file="binary")
    d.cont()

    # Send the candidate for every index
    p.sendline(str(candidate).encode()*23)

    # Wait for the breakpoint to be hit
    d.wait()

    # Now get the SBOX result at each index
    first_16_bytes = d.regs.xmm0.to_bytes(16, "little")
    last_16_bytes = d.regs.xmm1.to_bytes(16, "little")
    all_masked = first_16_bytes + last_16_bytes[9:]
    sboxes[:,i] = list(all_masked)

    d.detach()
    p.close()
```

Once we have sbox for each byte, we just have to find the character that maps to the bytes of the hardcoded data at each index:

```python
want = bytes.fromhex("a5 e7 f3 3f 8d e1 f5 0f ca 1b 12 65 0f e1 05 22 0f cf 14 36 e8 3c 3a")
for byte_index, masked_byte in enumerate(want):
    for candidate_index, masked_candidate in enumerate(sboxes[byte_index]):
        if masked_candidate == masked_byte:
            print(candidates[candidate_index], end="")
            break
    else:
        print("?", end="")
print()
```

Putting both parts together and running the script gives us the flag :)

```
$ python solv.py
HACKDAY{D0N7_637_rU57Y}
```