---
author: "frereit & Jan-Luca Gruber"
title: "Abusing Microsoft Warbird for Shellcode Execution"
date: "2024-11-07"
description: "In this blog post, we’ll be covering Microsoft Warbird and how we can abuse it to sneakily load shellcode without being detected by AV or EDR solutions."
tags:
    - "red-teaming"
    - "tooling"
toc: false
---

## Abstract

> In this blog post, we’ll be covering Microsoft Warbird and how we can abuse it to sneakily load shellcode without being detected by AV or EDR solutions. We’ll show how we can encrypt our shellcode and let the Windows kernel decrypt and load it for us using the Warbird API. Using this technique, you can hide your shellcode from syscall-intercepting EDR solutions allowing you to allocate executable memory, decrypt the shellcode, and jump to the decrypted shellcode all in one syscall, without ever having decrypted shellcode at any writeable memory region at any point during the execution of your process.


## Full Article

This article by a colleague and me was published at cirosec's blog:

**<https://cirosec.de/en/news/abusing-microsoft-warbird-for-shellcode-execution/>**

<!-- https://web.archive.org/web/20241114104038/https://cirosec.de/en/news/abusing-microsoft-warbird-for-shellcode-execution/ -->
