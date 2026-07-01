---
author: "frereit"
title: "How I write malware that evades AV and EDR"
date: "2026-06-30"
description: "Some notes from my personal experience without any scientific evidence."
tags:
    - "red-teaming"
    - "tooling"
toc: false
---

In this short post, I want to ramble about my approach to writing malware for Windows systems that are protected by some kind of Antivirus or <abbr title="Endpoint Detection and Response">EDR</abbr> software. I will use the term <abbr>AV</abbr> to refer generally to any endpoint products that are there to detect and mitigate malware attacks. Similarly, I use the term malware extremely broadly here. My experiments are done mostly with little C2 agents I'm cooking up in my free time for fun.

The notes in this post are based on my personal experience, which has a few caveats. Firstly, I don't really care about writing things that can be used against a huge range of targets at the same time. If you need this, you probably want to look into polymorphic malware, so that detection on one target cannot lead to the immediate detection on all other targets using simple signatures or hashes. Secondly, I am not concerned with loading existing malware, like commercial C2 beacons, as these are also commonly signatured and thus known to every AV product. Therefore, these notes are mostly applicable when writing novel malware for targeted operations.

## Blending In

Much of the online resources on malware development focus on hiding your malware. This may done using encryption, to avoid static detection, avoiding certain Windows APIs which are commonly associated with Malware, or injecting your malware into other trusted processes to fly under the radar.

I usually don't do this, unless there is a very specific reason or need for it (more on that below). Novel malware is by definition not known to AV databases, both in terms of their file hashes as well as their behavior. Modern AVs are (probably) going to see your injection attempts, and this will just raise your suspicion score without any real benefit. You actually want to be as normal as possible, as the included heuristics and machine learning models are tuned to trigger on any abnormalities.

This also means giving an icon, description, and other metadata to your binaries. For me, this alone has made the difference between being detected or not on multiple occasions. You can even go a step further and not only copy the metadata of a well-known binary, but also some of the assembly or strings within it. You don't need to actually call the original assembly at any point, but just including it can help throw off some machine learning models.

If you do end up needing some shellcode that is statically detected, you might want to embed it in an encrypted form in your binary. Try to use Windows APIs or some cryptography library instead of bringing your own crypto code. Custom crypto is a common point where signatures can be created, and is generally "not normal". So what if you call the Windows API to generate your keystream? What is an AV going to do with that? Of course, you might want to avoid calling Windows API for the actual decryption, as this leaks your plaintext shellcode to any watching AVs, but at least the keystream generation should be offloaded to a well-known and trusted library.


## Entropy

You should worry about the entropy in your binary. I don't care about the specific statistical meaning, but for my purposes entropy is just a measure of how random a bitstream looks. We can measure it in terms of "Bits per Byte", i.e., how many bits are needed to represent a full byte in an ideally compressed bitstream. This means that an entropy of 8 Bits per Byte is the maximum, meaning the data cannot be compressed at all, while 0 Bits per Byte is the minimum, where there is no information contained at all within the bitstream. A normal binary usually consists mostly of x86-64 assembly, which is not compressed. The entropy of x86-64 assembly is usually around 3-5 Bits per Byte, while encrypted data has an entropy of ~8 Bits per Byte. This difference is noticable to an AV, and often leads to detections. I've personally seen some AV products reject a binary that contains only known-good code and some high entropy blob, just based on the entropy. A simple trick to fix this is to split your encrypted data into two parts, where each part only contains roughly half of the bits of the data. This doubles the length of your bitstream, but reduces the entropy. At runtime, you then just take both parts and reconstruct the original ciphertext in memory. Here's some Python code to illustrate the idea:

```python
ENTROPY_MASK1 = 0b10100111
ENTROPY_MASK2 = 0b01011100
def entropy_reduce(high_entropy: bytes) -> bytes:
    low_entropy = bytearray(len(high_entropy) * 2)

    # every bit is included in at least one part
    assert ENTROPY_MASK1 | ENTROPY_MASK2 == 0xFF

    for i, v in enumerate(high_entropy):
        low_entropy[2 * i] = v & ENTROPY_MASK1
        low_entropy[2 * i + 1] = v & ENTROPY_MASK2

    return bytes(low_entropy)

def entropy_reconstruct(low_entropy: bytes) -> bytes:
    assert len(low_entropy) % 2 == 0
    high_entropy = bytearray(len(low_entropy) // 2)

    for i, (v1, v2) in enumerate(zip(low_entropy[::2], low_entropy[1::2])):
        # If the bit is set in either part, then it was set in the original input
        high_entropy[i] = v1 | v2

    return bytes(high_entropy)
```

This script is very basic and just serves as an example. You should probably pick new masks for every byte, so that not the same bits are zero in every byte. You can really make this as complex as you want: For instance, I've always wanted to build a thing where I encode each byte as a random (commonly used) x86-64 instruction, but just never had the need for it so far. You can check beforehand what entropy you are targeting, depending on where you will place the shellcode in your binary, and adjust the masks for each part so that the final entropy of the encrypted shellcode matches that of its surrounding bytes. The Python code above places 5 bits in the first part, and 4 bits in the second part, and so produces an entropy of 4.5 bits per byte, assuming a perfectly random input.

## Indirect Syscalls and Custom Call Stacks

There are many fancy tricks that can circumvent `kernel32.dll`. In my opinion, many of these are useless for targeted and unique malware and probably not as useful as advertised for generic malware either. This is in line with my first point, being that suspicious behavior alone gets you detected these days, since many detections are based on machine learning and heuristics. Thus, I generally avoid using these techniques as this leads to detections quite frequently, even when your malware does not even do anything malicious at all.
However, indirect syscalls and especially custom call stacks seem to still help due to bypassing some userland hooks, at least in some non-scientific testing. This post is not about the details of these techniques, you can find a plethora of other great resources on these topics elsewhere.

The main point of this section is some kind of intentionality about your evasion techniques. I use these 'l33t haxx0r' techniques only when I know exactly why it is needed and have experimentally verified that it has the expected benefit.

## Multiprocess Malware

Using multiple processes for your malware is one of the most undervalued techniques to reduce detections in my opinion. In [this blog post](https://sensepost.com/blog/2024/dumping-lsa-secrets-a-story-about-task-decorrelation/) this technique is referred to as "task decorrelation". Essentially, instead of doing many things with one process, do one thing with many processes. Detections are generally correlated to processes, and if no single process goes above some suspicion threshold, you might be able to get away with things that you otherwise wouldn't be able to do.

You will need to adjust this to your use-case, but generally just try to split things up into multiple processes when possible. Be mindful of how you are creating your multiple processes, as child process relations are usually tracked by AVs and thus defeat this decorrelation. The same goes for communication between the processes. Here I just get creative, there are so many ways to spawn processes and communicate between them. You can use COM objects, Windows Events (for boolean signals), HTTP, Named Pipes, TCP, and thousands of other things. 

## Wrap-Up

I wrote this post because the topic came up in conversation recently I wanted to write down my thoughts. None of this is well-researched or new knowledge or even properly evaluated, it's just my personal experience playing with malware and AVs in my free time. Personally, just forgetting I am writing malware and not falling for the next evasion technique hype is probably 80% of the evasion I ever need.

To summarize: 

- Pragmatism, i.e., using the tools and libraries that are already well-established and trusted, leads to less unknown code and unique behaviors.
- Intentionality, i.e., using special APIs or tricks only when there is a good reason, leads to less suspicious behavior.
- Masquerading as well-known software by including their code and metadata gives you a higher trust baseline than completely new code.

<small>written by a human</small>
