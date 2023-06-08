---
layout: post
title: 404CTF 2023 | La Feuille Blanche
image: /assets/images/404ctf/la-feuille-blanche/cover.png
date: 2023-06-08 12:38:00
categories: [404ctf, pwn]
---

This challenge was part of the [404CTF 2023](https://www.404ctf.fr/), organized by the General Directorate for External Security (DGSE) and Télécom SudParis.

# Challenge Description

![Challenge Description]({{site.baseurl}}/assets/images/404ctf/la-feuille-blanche/description.png)

When we start the program, it hangs with no message, and exits when we press enter. We will have to reverse the file to understand what it is actually doing.

![checksec output]({{site.baseurl}}/assets/images/404ctf/la-feuille-blanche/checksec.png)

The PIE is not enabled, no canary is present, but the stack is not executable... I can smell a **buffer overflow** with a **ROP chain** here ! 🧐

Our file has **Partial RELRO**, which means that the [GOT](https://en.wikipedia.org/wiki/Global_Offset_Table) table will be writable as explained [here](https://ctf101.org/binary-exploitation/relocation-read-only/).

# Reverse engineering

![Ghidra decompiled main function]({{site.baseurl}}/assets/images/404ctf/la-feuille-blanche/doRead.png)

It could not be simpler than that ! The buffer is `24 bytes` long, and we can write `80 bytes` on it, as the architecture is 32 bits, we can then write a ROP chain of `(80-24)/4 = 14` gadgets. Let's see what we can do with that.

# Exploitation

![ROPgadget output]({{site.baseurl}}/assets/images/404ctf/la-feuille-blanche/gadgets.png)

We start by generating all the gadgets in a file, as we will probably search through them a lot. The first idea (and surely the simplest) is to search for a `int 0x80` gadget, which could allow us to run some syscalls. Unfortunately, the binary desn't have such gadget. I wonder where we could find one ? 🤔

> A common technique to issue a system call when the binary doesn't contain `int 0x80` (or `syscall` for x86-64) is to **use the libc**. In our case libc addresses are randomized due to ASLR, so we will find a way to bypass this mitigation.
> This can be done either by leaking an address from the libc or by **using an address already present on the memory or registers**

<div class="row-container column-reverse">
	<div class="flex-2">
{% markdown %}

{% endmarkdown %}
	</div>
	<div>
{% markdown %}

{% endmarkdown %}
	</div>
</div>


