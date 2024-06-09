---
author: "frereit"
title: "AES-GCM and breaking it on nonce reuse"
date: "2024-06-09"
description: "In this post, we will look at how the security of the AES-GCM mode of operation can be completely compromised when a nonce is reused."
tags:
    - "cryptography"
    - "algorithm"
toc: true
---

## An overview of this article (TL;DR)

TL;DR: AES-GCM is great, as long as every nonce (**n**umber used **once**) is truly unique. Once a nonce is reused, AES-GCM completely falls apart.

If you've ever worked with AES-GCM, you may have heard that reusing a nonce can lead to catastrophic security failures. In this post, we will look at how exactly all security guarantees of AES-GCM can be broken when a nonce is reused even once.

First, we'll quickly go over AES, then explain AES-GCM in detail. We'll then derive some formulas for the AES-GCM authentication tags and see how we can authenticate any message we want as soon as a nonce is reused.

This post will be somewhat math heavy, especially as we get to the nonce reuse attack. I'll try my best to explain any concepts not covered by high-school math, and I'll skip over any details of the algorithms, as these are best understood by reading the original papers.

## AES

If you're reading this, chances are you know what <abbr title="Advanced Encryption Standard">AES</abbr> is. It is the most widely used symmetric encryption algorithm and is almost always the symmetric cipher used when communicating over HTTPS. 

AES is a block cipher, which means it encrypts and decrypts data in fixed-size blocks. The block size for AES is 128 bits, which is 16 bytes. This means that given a key, the AES algorithm can be used to transform a 128-bit block of data into another 128-bit block of data, and back again. We arbitrarily call this process encryption and decryption, respectively. There's no intrinsic property of AES that assigns one direction to encryption and the other to decryption. It is important to understand that AES is a bijective function, meaning *any* 128-bit block of data can be encrypted into a 128-bit block of data, and that *any* 128-bit block of data is a valid ciphertext that can be decrypted again. This is a fundamental property of block ciphers and important to understand.

Because every single possible block of 128-bit data can be decrypted using AES, it is absolutely incorrect to assume that just because you *can* decrypt some ciphertext, that it was indeed encrypted using the key you have. Anyone "in the middle" of a transmission can just replace the ciphertext, even if they don't have the key, and AES won't tell you that that's happened.

There are three key sizes you can choose from when using AES: 128, 192, and 256. The key size changes some internal parameters of the algorithm, but the basic structure is the same. In this blog post, we will only be considering AES-128 but the same principles apply to the other key sizes as well, and for that matter, to any block cipher.

<figure>
<img loading="lazy" src="/img/aes/aes-block-cipher.svg" alt="AES is a bijective function parameterize by a key" data-ffwidth="51%" style="width: 50%;" id="aes-block-cipher">
<figcaption style="font-size: 0.8em;">AES is a bijective function parameterized by a key</figcaption>
</figure>

It is important to understand that AES-128 is just that, a cipher that encrypts and decrypts a single 128-bit block of data. AES does not specify how to encrypt multiple blocks of data using a single key, nor does it authenticate the data. It is a simple bijective function parameterized by a key, nothing more, nothing less.

You can play with the following widget to see how AES-128 works. The widget allows you to encrypt and decrypt a single block of data using a key of your choice.

<p id="demo-raw-aes">
<noscript><strong>You have JavaScript disabled! Although you will be able to read the content, the widgets will not work. Please consider enabling JavaScript. There is no tracking or anything on this site, it'll just be used to render these widgets.</strong></noscript>
</p>
<script type="module">
    import { raw_aes_widget } from "/js/aesgcm_widgets.js";
    raw_aes_widget(document.getElementById("demo-raw-aes"));
</script>

In summary, we can treat AES-128 as a simple black box that encrypts and decrypts 128-bit blocks of data using a key. It is a building block that can be used to build more complex cryptographic systems, but it is not a complete cryptographic system in itself.

## GCM

When using a block cipher, we want to be able to encrypt arbitrary amounts of data, and we want to ensure that the encrypted data cannot be tampered with. This is where modes of operation come into play. A mode of operation is a way to use a block cipher to encrypt and authenticate data. There are many different modes of operation, but in this post, we will focus on the Galois/Counter Mode, or GCM for short.

GCM is a method for authenticated encryption with associated data (AEAD). "Authenticated encryption" means that the mode of operation allows us to validate that a given ciphertext was indeed generated using the secret key, and that it has not been modified. This is called "authenticating" the ciphertext and is essential for secure communication. Without it, a bad actor could modify the ciphertext and the recipient would not be able to detect it, leading to garbled plaintext in the best case, and a huge security issue in the worst case.

The second part, "with associated data", means that we can also authenticate additional data that is not encrypted. This is almost a byproduct of the way GCM works, but it is a very useful feature. For example, when sending a message, we might want to encrypt the message but keep the sender in plaintext. Think of a letter you're mailing, where the contents are "protected" but the sender is plainly visible. By using AES-GCM, we are able to authenticate not only the ciphertext but also the sender so that the recipient can be sure that the message was indeed sent by the sender and that it is intended for them, even if the sender is not part of the ciphertext.

In this post, we'll look at the two parts of GCM (encryption and authentication) seperately. We'll start by seeing how encryption works with AES-GCM, where the nonce comes into play, and how the encryption breaks when a nonce is reused. After that, we'll dive into the authentication part and see how it can also be broken when a nonce is reused.

### GCM encryption

GCM, like all modes of operation, provides a way to encrypt and decrypt arbitrary amounts of data using the underlying block cipher.

To do this, GCM uses the block cipher (in our case, AES-128) to generate a sequence of random-looking bits that are as long as the plaintext. This is called the keystream and it can be generated deterministically using the key (and a nonce, which we will get to in a bit), which means although it looks random, the recipient of a message in possesion of the key is able to calculate the same keystream. To encrypt the plaintext, we take the plaintext and XOR it with the keystream. XOR (⊕) is a simple operation that takes any two bits and returns 1 if exactly one of the bits is 1, and 0 otherwise. It, conveniently, is its own inverse. This means that if we generate by XORing the plaintext and keystream (`ciphertext = plaintext ⊕ keystream`), we can decrypt the ciphertext, we generate the keystream used during the encryption and XOR it with the cipertext we received: `ciphertext ⊕ keystream = (plaintext ⊕ keystream) ⊕ keystream = plaintext`. So, technically, in GCM, we don't actually encrypt the plaintext using the block cipher, we encrypt it using the keystream. The block cipher is only used to generate the keystream.

However, there's a problem: Let's assume for a moment that we have two plaintexts `p1` and `p2` and we want to encrypt them both using the same key. If the keystream was only generated using the key, then the keystream for `p1` would be the same as the keystream for `p2`. The ciphertexts would then be `c1 = p1 ⊕ keystream` and `c2 = p2 ⊕ keystream`. At first glance, this seems fine, but it is not. If an attacker knows the plaintext `p1` and the ciphertext `c1`, then they can compute the keystream by XORing `p1` and `c1` together (`keystream = p1 ⊕ c1`) and then decrypt `c2` by XORing `c2` with the keystream (`p2 = c2 ⊕ keystream = c2 ⊕ (p1 ⊕ c1)`). This is a huge security issue, as it allows an attacker to decrypt any ciphertext they have the plaintext for, without knowing the key. This is why we need to introduce a **nonce**.

A nonce, short for "number used once", is a random number transfered along with each ciphertext that may never be reused (under the same key). We use the nonce as an additional input to the block cipher when generating the keystream so that for each ciphertext, the keystream is different. This means that even if an attacker knows the plaintext and ciphertext for one message, they cannot use that information to decrypt any other ciphertext. When a nonce is reused, however, the keystream is the same, and an attacker can use the same technique as above to decrypt any ciphertext that was encrypted using the same nonce.

Let's take a look at an example! First, we choose a nonce and generate a keystream using the key from earlier and the chosen nonce:

<p id="demo-ctr-mode-nonce-reuse">
<noscript><strong>You have JavaScript disabled! Although you will be able to read the content, the widgets will not work. Please consider enabling JavaScript. There is no tracking or anything on this site, it'll just be used to render these widgets.</strong></noscript>
</p>
<script type="module">
    import { ctr_mode_nonce_reuse_widget } from "/js/aesgcm_widgets.js";
    ctr_mode_nonce_reuse_widget(document.getElementById("demo-ctr-mode-nonce-reuse"));
</script>

Notice how `c2 ⊕ p1 ⊕ c1` is the same as `p2` as long as `p1` is long enough? This is the security issue we were talking about. If the nonce is reused, an attacker only needs a single pair of plaintext and ciphertext to decrypt any other ciphertext that was encrypted using the same key and nonce. Additionally, by obtaining the keystream, an attacker is able to create their own ciphertext for any plaintext they want, simply by XORing the plaintext with the recovered keystream. Therefore, encryption is trivially broken when a nonce is reused.

#### Keystream generation

Although not necessary for understanding the security issue, let's look at how the keystream is generated in GCM. In GCM, we start off with some initial block of 16 bytes called `Y`<sub>`0`</sub> that is calculated from the given nonce. Incrementing this block means taking the last 4 bytes and interpreting them as a 32-bit big-endian integer and incrementing that integer by 1. We start off by incrementing the initial block and then encrypting it using AES-128. This will gives us 16 bytes of output, which we then use as the first 16 bytes of the keystream. We then increment the block again and encrypt it again to get the next 16 bytes of keystream, and so on. This process is repeated until the entire plaintext is encrypted. Note that if the plaintext falls short of a full 16 bytes, we simply only take as many bytes as we need from the keystream instead of the full 16 bytes. This process of "counting up" and encrypting the resulting block to get the keystream is the "Counter Mode" part of Galois/Counter Mode.

<figure>
<img loading="lazy" src="/img/aes/gcm-ctr.svg" alt="GCM uses a simple counter to generate consecutive keystream blocks" data-ffwidth="99%" style="width: 100%;" id="gcm-ctr-mode">
<figcaption style="font-size: 0.8em;">GCM uses a simple counter to generate consecutive keystream blocks</figcaption>
</figure>

As you can see, the generated keystream only depends on `Y`<sub>`0`</sub>, which in turn only depends on the nonce, and the key. This means that if the nonce is reused across different messages, the keystream will be the same for both messages, and an attacker can use the technique as above to decrypt any ciphertext that was encrypted using the same nonce.


##### `Y`<sub>`0`</sub> calculation

I told you before that `Y`<sub>`0`</sub> is calculated from the nonce, but I didn't tell you how. In the simple case, the supplied nonce is 12 bytes long (e.g. `deadbeefcafeaffebadbabe0`). In that case, `Y`<sub>`0`</sub> is the nonce with a 4-byte big endian 1 appended to it, so `Y`<sub>`0`</sub>` = nonce || 0x00000001`. If the nonce is not exactly 12 bytes long, we generate `Y`<sub>`0`</sub> by passing it through a kind-of hash function called `GHASH`. We'll look at `GHASH` in more detail later but for now, just imagine that `GHASH` takes a nonce of any length and spits out a 16-byte block that we can use as `Y`<sub>`0`</sub>.

<p id="demo-gcm-y0-calculation">
<noscript><strong>You have JavaScript disabled! Although you will be able to read the content, the widgets will not work. Please consider enabling JavaScript. There is no tracking or anything on this site, it'll just be used to render these widgets.</strong></noscript>
</p>
<script type="module">
    import { gcm_y0_calculation_widget } from "/js/aesgcm_widgets.js";
    gcm_y0_calculation_widget(document.getElementById("demo-gcm-y0-calculation"));
</script>

The generated `Y`<sub>`0`</sub> is then used to generate the keystream as described above.

#### Recap

We've now seen how the encryption part of GCM works. We've seen that the nonce is used together with the key to generate a keystream that is then used to encrypt the plaintext. We've also seen that if the nonce is reused, an attacker can use a single known plaintext-ciphertext pair to decrypt any other ciphertext that was encrypted using the same nonce. Once an attacker has obtained the keystream, they can also use it to encrypt any plaintext they want, so there is no guarantee that the plaintext was indeed generated by the sender in possession of the key.

### GCM authentication

The second and equally important part of GCM is the authentication. This means that we are able to validate that a given ciphertext was indeed generated using the secret key, and that it has not been modified. At the risk of repeating myself, remember that the encryption part of GCM only ensures that the ciphertext cannot be decrypted without the key, but it does not ensure that is has not been tampared with. The encryption operation is a simple XOR operation, so if an attacker changes a single bit in the ciphertext from a `0` to a `1`, the corresponding bit in the plaintext will also change. This means that even though the ciphertext cannot be decrypted without the key, an attacker can still modify the ciphertext and the recipient would not be able to detect it. With a single known plaintext-ciphertext pair, an attacker is even able to recover the entire keystream and thus encrypt any plaintext they want. Hence, we need to authenticate the ciphertext.

#### Galois field arithmetic

A core part of the authentication in GCM is the use of Galois field arithmetic, the other part of Galois/Counter Mode. Galois field arithmetic is just a fancy name for a kind of maths where we don't have infinite numbers like in the real numbers, but instead we have a finite number of elements. This is why sometimes Galois fields are also called "finite fields". 

##### `GF(2)`

The simplest example of a Galois field is the field of integers modulo `2`. This means that we only have two elements, `0` and `1`. Forget all other numbers, only `0` and `1` exist when we're talking about `GF(2)`. Because this is a new number system, we have to definie how mathematical operations work in it. If no other numbers exist, what is `1 + 1`?

We *define* addition of numbers in these fields to be the result of adding the numbers in the real numbers and then taking the result modulo `2`. The modulo operation simply takes the remainder of a whole number divison. For example, in the real numbers, `5 = 2 * 2 + 1`, so `5 = 1 (mod 2)`. Let's look at how this looks in an addition table:

<table>
<tr>
    <th>+</th>
    <th>0</th>
    <th>1</th>
</tr>
<tr>
    <th>0</th>
    <td>0</td>
    <td>1</td>
</tr>
<tr>
    <th>1</th>
    <td>1</td>
    <td>0</td>
</tr>
</table>

As you can see, `0 + 0 = 0`, `0 + 1 = 1`, `1 + 0 = 1`, and `1 + 1 = 0`. You might recognize this as the XOR operation that we used to encrypt the plaintext with the keystream. This is no coincidence, as the XOR operation is exactly the addition operation in the Galois field of integers modulo `2`. This means that when we XOR two numbers together, we can also think of it as adding them together in the Galois field of integers modulo `2`. To make it clear that we are working in a different number system, we don't use the `+` symbol for addition in Galois fields, but instead use the `⊕` symbol. You might have seen this symbol as the XOR operation, and now you know that it is exactly the same as addition in the Galois field of integers modulo `2`.

Now, let's look at how we *define* multiplication in the Galois field of integers modulo `2`. We define it to be the result of multiplying the numbers in the real numbers and then taking the result modulo `2`. Let's look at how this looks in a multiplication table:

<table>
<tr>
    <th>⋅</th>
    <th>0</th>
    <th>1</th>
</tr>
<tr>
    <th>0</th>
    <td>0</td>
    <td>0</td>
</tr>
<tr>
    <th>1</th>
    <td>0</td>
    <td>1</td>
</tr>
</table>

Again, you might notice that this is exactly the same as the AND operation. The result of multiplying two numbers in `GF(2)` is `1` if and only if both numbers are `1`. This means that when we AND two numbers together, we can also think of it as multiplying them together in the Galois field of integers modulo `2`. Analogously to the addition operation, where we use the `⊕` symbol, we use the `⨂` symbol to represent multiplication in Galois fields.

##### `GF(2`<sup>`128`</sup>`)`

We can also define Galois fields with more than two elements. For example, we can define a Galois field with `2`<sup>`128`</sup> elements. This means that we have `2`<sup>`128`</sup> different numbers, which is just to say that we use 128 bits (16 bytes!) to represent each number. You might already notice that this is exactly the same as the block size of AES. As you'll see later, this is no coincidence, because we'll start interpreting the 128-bit blocks of data as elements represented by numbers in `GF(2`<sup>`128`</sup>`)`.

First, though, we need to define addition and multiplication in `GF(2`<sup>`128`</sup>`)` just like we did for `GF(2)`. One way to think of elements in `GF(2`<sup>`128`</sup>`)` is as polynomials with coefficients in `GF(2)`. This is just a definition, we have this set of `2`<sup>`128`</sup> things, and we say that each of the things corresponds to some polynomial. This means that we can represent each element in `GF(2`<sup>`128`</sup>`)` as a polynomial of degree at most `127` with coefficients in `GF(2)`. So, some elements of `GF(2`<sup>`128`</sup>`)` can be represented like so:

- `0 ⋅ x`<sup>`0`</sup>` = 0`.
- `1 ⋅ x`<sup>`0`</sup>` = 1`.
- `x`<sup>`4`</sup>` + x`.
- `x`<sup>`127`</sup>` + x`<sup>`126`</sup>` + x`<sup>`125`</sup>.

Because we've defined the the coefficients to be in `GF(2)`, they are all either `0` or `1`. Another way to look at this is that `x`<sup>`i`</sup> is either in the polynomial or it is not, for each `i` from `0` to `127`. This means that we can represent each element in `GF(2`<sup>`128`</sup>`)` as a 128-bit value, where each bit tells us if a certain power of `x` is in the polynomial or not. Different standards use different ways to assign the bits to the powers of `x` but the GCM standard uses a kind-of reversed order, so that the most significant bit of the 128-bit value corresponds to `x`<sup>`0`</sup>, the next bit to `x`<sup>`1`</sup>, and so on, up to the least significant bit corresponding to `x`<sup>`127`</sup>. Let's encode the previous polynomials in this way as hexadecimal values:

- `0` is `00000000000000000000000000000000` because no powers of `x` are in the polynomial.
- `1` is `80000000000000000000000000000000` because `x`<sup>`0`</sup> is in the polynomial, which is the most significant bit.
- `x`<sup>`4`</sup>` + x` is `48000000000000000000000000000000`.
- `x`<sup>`127`</sup>` + x`<sup>`126`</sup>` + x`<sup>`125`</sup> is `00000000000000000000000000000007`.

We now have a way of representing each of the `2`<sup>`128`</sup> elements of `GF(2`<sup>`128`</sup>`)` as a polynomial. To define addition, we use the polynomial representation, which already has a well-defined addition operation. Remember, all coefficients are in `GF(2)`, so we add them together using the addition operation we defined earlier, for example `(x`<sup>`2`</sup>` + x) + (x`<sup>`4`</sup>` + x`<sup>`2`</sup>` + 1) = x`<sup>`4`</sup>` + x + 1`. The result is a polynomial of degree at most `127` with coefficients in `GF(2)`, so it is a valid element in `GF(2`<sup>`128`</sup>`)`. Note that if a power of `x` appears in both polynomials, it will be cancelled out, so for example `(x`<sup>`2`</sup>`) + (x`<sup>`2`</sup>`) = 0`. If it appears in exactly one of the polynomials, it will be in the result. This is exactly the same as the XOR operation, so we can again think of addition in `GF(2`<sup>`128`</sup>`)` as the XOR operation on the 128-bit values representing the polynomials.

You can try it out for yourself here. Enter two polynomials or their hexadecimal representations and see the result of adding them together:

<p id="demo-gf2-128-addition">
<noscript><strong>You have JavaScript disabled! Although you will be able to read the content, the widgets will not work. Please consider enabling JavaScript. There is no tracking or anything on this site, it'll just be used to render these widgets.</strong></noscript>
</p>

<script type="module">
    import { gf2_128_addition_widget } from "/js/aesgcm_widgets.js";
    gf2_128_addition_widget(document.getElementById("demo-gf2-128-addition"));
</script>

Hopefully you're able to convince yourself that adding these polynomials is exactly the same as XORing the 128-bit values representing them. This is the addition operation in `GF(2`<sup>`128`</sup>`)`.

Now, let's take a look at multiplication. Multiplication, just like addition, works by interpreting the field elements as polynomials and then multiplying the polynomials together. For example, `(x`<sup>`2`</sup>` + x) ⋅ (x`<sup>`4`</sup>` + 1) = x`<sup>`6`</sup>` + x`<sup>`5`</sup>` + x`<sup>`2`</sup>` + x`. We get this result by multiplying all the terms in the first polynomial with all the terms in the second polynomial and then adding the results together. In this case, the result is a polynomial with degree `6` and coefficients in `GF(2)`, so it is a valid element in `GF(2`<sup>`128`</sup>`)`. However, look at what happens when we multiply `x`<sup>`127`</sup> by `x`: `x`<sup>`127`</sup>` ⋅ x = x`<sup>`128`</sup>. This poses a problem because we defined `GF(2`<sup>`128`</sup>`)` to have elements of degree at most `127` but this polynomial is of degree `128`. So `x`<sup>`128`</sup> is not an element which we can represent as a 128-bit block of data.
Instead, we need to add another step to the multiplication operation: 

After we multiply the polynomials together, we divide the result by a special polynomial called the "reduction polynomial" and take the remainder as the result instead. The reduction polynomial must be defined along with the field. It is an irreducible polynomial, which means that it isn't the product of any two polynomials (like how prime numbers aren't the product of any two other numbers) and has degree 128, so that the remainder of a division operation is always of degree at most 127. The GCM standard defines the reduction polynomial to be `x`<sup>`128`</sup>` + x`<sup>`7`</sup>` + x`<sup>`2`</sup>` + x + 1` for the field `GF(2`<sup>`128`</sup>`)` used in GCM.

In this case, where we are trying to reduce `x`<sup>`128`</sup>, it's actually quite easy to see that dividing `x`<sup>`128`</sup> by `x`<sup>`128`</sup>` + x`<sup>`7`</sup>` + x`<sup>`2`</sup>` + x + 1` will result in a remainder of `x`<sup>`7`</sup>` + x`<sup>`2`</sup>` + x + 1` because `x`<sup>`128`</sup> fits exactly once into the reduction polynomial, leaving a remainder of `x`<sup>`7`</sup>` + x`<sup>`2`</sup>` + x + 1`. Multiplying `x`<sup>`128`</sup> by `1` and adding the remainder confirms this:

`1 ⋅ (x`<sup>`128`</sup>`) + (x`<sup>`7`</sup>` + x`<sup>`2`</sup>` + x + 1) = x`<sup>`128`</sup>` + x`<sup>`7`</sup>` + x`<sup>`2`</sup>` + x + 1`.

For more complex cases, we need to use polynomial long division to divide the result by the reduction polynomial and take the remainder as the result. This is a bit more involved, but it is exactly the same as long division with real numbers, just with polynomials instead. I won't go into the details here because we can just let the computer do the work for us, but if you're interested, you can look up polynomial long division on the internet and try to apply it to coefficients in `GF(2)` instead of real numbers[^1].

If we look at the multiplication in `GF(2`<sup>`128`</sup>`)` from the perspective of the 128-bit blocks of data, instead of the polynomials, the operation is sometimes referred to as "Carry-less multiplication", because it corresponds to the multiplication of the 128-bit blocks of data, where all carry values are discarded instead of propagated during the multiplication. In this post, we'll stick to the polynomial representation, but it's good to know that the operation is also called "Carry-less multiplication" or "CLMUL", especially if you're looking at the AES-NI instruction set of modern CPUs. The symbol for multiplication in Galois fields is `⨂`, so we'll use that in the following figures.

[^1]: In real implementations, we can even be a bit smarter about how we multiply the polynomials together, so that we don't need to do the long division step. Instead, we reduce the result at each step of the multiplication, so that the result is always of degree at most 127 using the Russian peasant multiplication algorithm. Check out the [example code on Wikipedia](https://en.wikipedia.org/wiki/Finite_field_arithmetic#C_programming_example) if you'd like to learn more.

Let's go through another example. Enter two polynomials and see the result of multiplying them together:

<p id="demo-gf2-128-multiplication">
<noscript><strong>You have JavaScript disabled! Although you will be able to read the content, the widgets will not work. Please consider enabling JavaScript. There is no tracking or anything on this site, it'll just be used to render these widgets.</strong></noscript>
</p>
<script type="module">
    import { gf2_128_multiplication_widget } from "/js/aesgcm_widgets.js";
    gf2_128_multiplication_widget(document.getElementById("demo-gf2-128-multiplication"));
</script>

That covers the basics of Galois field arithmetic. We've seen that we can add and multiply elements in `GF(2`<sup>`128`</sup>`)` just like we can add and multiply real numbers, but with the added step of reducing the result by a reduction polynomial. Importantly, we can also think of addition as the XOR operation, which is why it can also be represented by the `⊕` symbol. Multiplication is represented by the `⨂` symbol in the following figures.

#### GHASH

Now that we have the basics of Galois field arithmetic down, we can look at the `GHASH` function. `GHASH` is a function defined in the GCM standard that takes a key and arbitrary amounts of data and spits out a 128-bit block of data. This block of data is then used in the GCM standard to authenticate the ciphertext and the associated data. 

To use `GHASH`, we first need to derive a 128-bit block that we can use as the `GHASH` key `H`. This is done by encrypting a block of 16 null bytes using AES and the AES key. This block is then interpreted as a polynomial and used as the `GHASH` key `H` for the rest of the `GHASH` computation:

<figure>
<img loading="lazy" src="/img/aes/h-key.svg" alt="The GHASH key H is derived by encrypting a block of 16 null bytes using AES-128 and the AES key" data-ffwidth="51%" style="width: 50%;">
<figcaption style="font-size: 0.8em;">The GHASH key H is derived by encrypting a block of 16 null bytes using AES-128 and the AES key</figcaption>
</figure>

To compute `GHASH`, we first need to represent the data we want to authenticate as a sequence of 128-bit blocks. This is done by splitting the data into 128-bit blocks and then padding the last block with null bytes if it is not already 128 bits long. We do this separately for the associated data and the ciphertext, so for example if we wanted to authenticated the associated data `deadbeef` and the ciphertext `cafeaffe`, we'd use the blocks `deadbeef000000000000000000000000` and `cafeaffe000000000000000000000000` as the input to `GHASH`. To make sure the size of the data is not lost, we add one more block at the end that contains the length of the associated data in bits as a 64-bit big-endian integer and the length of the ciphertext in bits as a 64-bit big-endian integer concatenated together, so in this case `00000000000000200000000000000020` for the associated data `deadbeef` and the ciphertext `cafeaffe`.

To start the computation, we initialize a `GF(2`<sup>`128`</sup>`)` element `Q` to `0`. We then process the prepared blocks in sequence. The blocks from the associated data are processed first, followed by the blocks from the ciphertext. The length block is processed last. For each block, we interpret the block as a `GF(2`<sup>`128`</sup>`)` element and add it to `Q` using the addition operation in `GF(2`<sup>`128`</sup>`)` (which is just the XOR operation) and then multiply `Q` by the `GHASH` key `H` using the multiplication and reduction operation we defined earlier.

<figure>
    <img loading="lazy" src="/img/aes/ghash.svg" alt="The GHASH function processes 128-bit blocks in order" data-ffwidth="99%" style="width: 100%;">
    <figcaption style="font-size: 0.8em;">The GHASH function processes 128-bit blocks in order</figcaption>
</figure>

The `result` of the `GHASH` function is the final value of `Y` after processing all the blocks. For security reasons that will hopefully become clear later, we cannot use the `result` directly as the authentication tag. Instead, we encrypt the `Y`<sub>`0`</sub> block from earlier using the AES key and XOR the encrypted `Y`<sub>`0`</sub> block with the `result` to get the final authentication tag. This is the value that is sent along with the ciphertext and the associated data to the recipient, who can then use the same key to compute the `GHASH` function and verify that the authentication tag is correct. An attacker who does not know the key cannot modify the ciphertext or the associated data without the recipient noticing, because they would not be able to compute the correct authentication tag, because they cannot derive `H` and the encrypted `Y`<sub>`0`</sub> block.

##### Formula for GHASH

We can also express the `GHASH` function as a formula. Let `H` be the `GHASH` key and `U`<sub>`i`</sub> be the `i`-th prepared block. So, in the example above, `U`<sub>`0`</sub> would be `deadbeef000000000000000000000000`, `U`<sub>`1`</sub> would be `cafeaffe000000000000000000000000`, and `U`<sub>`2`</sub> would be `00000000000000200000000000000020`. 

We can build the formula for `GHASH` iteratively:

1. First, we initialize `Q` to `0`: `Q ← 0`.
2. Then, for the first block, we add it to `Q`: `Q ← Q ⊕ U`<sub>`0`</sub> (which is the same as `Q = U`<sub>`0`</sub> because `Q` is `0`).
3. We then multiply `Q` by `H`: `Q ← Q ⨂ H = (U`<sub>`0`</sub>`) ⨂ H`.
4. For the second block, we add it to `Q`: `Q ← Q ⊕ U`<sub>`1`</sub>` = ((U`<sub>`0`</sub>`) ⨂ H) ⊕ U`<sub>`1`</sub>.
5. Again, we multiply `Q` by `H`: `Q ← Q ⨂ H = (((U`<sub>`0`</sub>`) ⨂ H) ⊕ U`<sub>`1`</sub>`) ⨂ H`.
6. We can continue this process for all the blocks and the final result is the `GHASH` value. The formula for `GHASH` is then: `Q = (((((U`<sub>`0`</sub>` ⨂ H) ⊕ U`<sub>`1`</sub>`) ⨂ H) ⊕ U`<sub>`2`</sub>`) ⨂ H) ⊕ ...`

Take some time to look at the formula and see if you can convince yourself that it indeed the same as the graphical representation above. 

Multiplication and addition in `GF(2`<sup>`128`</sup>`)` follows the usual laws of multiplication and addition, so we can distribute the multiplication of `H` over the additions. This means that `(((U`<sub>`0`</sub>`) ⨂ H) ⊕ U`<sub>`1`</sub>`) ⨂ H = (U`<sub>`0`</sub>` ⨂ H`<sup>`2`</sup>`) ⊕ (U`<sub>`1`</sub>` ⨂ H)`. 

We can apply this rule to the formula above to get a more compact formula for `GHASH`:

`Q = (U`<sub>`0`</sub>` ⨂ H`<sup>`n+1`</sup>`) ⊕ (U`<sub>`1`</sub>` ⨂ H`<sup>`n`</sup>`) ⊕ ... ⊕ (U`<sub>`n-1`</sub>` ⨂ H`<sup>`2`</sup>`) ⊕ (U`<sub>`n`</sub>` ⨂ H)`.

Lastly, we have to XOR the result with the encrypted `Y`<sub>`0`</sub> block to get the final authentication tag. We have to add the encrypted `Y`<sub>`0`</sub> block to the result to get the final authentication tag `T`, because adding in `GF(2`<sup>`128`</sup>`)` is equal to the XOR operation:

`T = Q ⊕ E`<sub>`k`</sub>`(y`<sub>`0`</sub>`) = (U`<sub>`0`</sub>` ⨂ H`<sup>`n+1`</sup>`) ⊕ ... ⊕ (U`<sub>`n`</sub>` ⨂ H) ⊕ E`<sub>`k`</sub>`(y`<sub>`0`</sub>`)`.

Now that we have a formula for `GHASH`, we can use it to compute the authentication tag for the ciphertext and the associated data. Let's take a look at an example! Enter some key, nonce, associated data, and ciphertext and see the authentication tag computed using the `GHASH` function:

<p id="demo-ghash">
<noscript><strong>You have JavaScript disabled! Although you will be able to read the content, the widgets will not work. Please consider enabling JavaScript. There is no tracking or anything on this site, it'll just be used to render these widgets.</strong></noscript>
</p>
<script type="module">
    import { ghash_widget } from "/js/aesgcm_widgets.js";
    ghash_widget(document.getElementById("demo-ghash"));
</script>

Okay, that was a lot! We've now seen how the `GHASH` function works and how it is used to authenticate the ciphertext and the associated data. We've also seen that we can represent the `GHASH` function as a formula that we can use to compute the authentication tag in `GF(2`<sup>`128`</sup>`)`. To verify the authenticity of the ciphertext and the associated data, the recipient can compute the `GHASH` function using the same key and the same nonce and compare the result to the authentication tag. If the two values match, the recipient can be sure that the ciphertext and the associated data have not been tampered with and that they were indeed generated by the sender in possession of the key.

### Recap

We've now seen how GCM works. It allows us to encrypt and authenticate data using a secret key, and detect if the encrypted data has been tampered with.

Enter any plaintext, key, and nonce and see the ciphertext and authentication tag computed using AES-GCM[^2]. This time, unlike in plain AES, when you change the ciphertext or authentication tag, the decryption will fail because the authentication tag will not match:

[^2]: For simplicity, I've not included the associated data in this widget. The associated data is used in the computation of the authentication tag just like the ciphertext, so it really doesn't matter for this demonstration.

<p id="demo-aes-gcm">
<noscript><strong>You have JavaScript disabled! Although you will be able to read the content, the widgets will not work. Please consider enabling JavaScript. There is no tracking or anything on this site, it'll just be used to render these widgets.</strong></noscript>
</p>
<script type="module">
    import { aes_gcm_widget } from "/js/aesgcm_widgets.js";
    aes_gcm_widget(document.getElementById("demo-aes-gcm"), "abadbabe");
</script>

If you've made it this far into the blog post, now may be a good time to take a break and let all the information sink in before we continue on to the attack on AES-GCM when a nonce is reused. If you have any questions, feel free to [send me a toot](https://infosec.exchange/@fre).

<marquee scrollamount=3 scrolldelay=60 direction=right behavior=alternate>☕☕☕☕☕☕☕☕☕</marquee>

Alright, let's continue to the attack!

## Nonce Reuse

We have now seen how AES-GCM works and how the authentication tag is computed. We have also seen that the nonce is used in the computation of the authentication tag. But what happens if the nonce is reused?

Let's assume two authentication tags `T1` and `T2` are computed using the same key and nonce. For simplicitly, let's assume the blocks used in the `GHASH` computation were `U1`<sub>`0`</sub>, `U1`<sub>`1`</sub> and `U1`<sub>`2`</sub> for the first tag and `U2`<sub>`0`</sub>, `U2`<sub>`1`</sub> and `U2`<sub>`2`</sub> for the second tag. In practice, the number of blocks used in the `GHASH` computation is (almost) irrelevant, but for this example, we'll stick to three blocks.

Let's write out the formula for the first tag `T1`:

`T1 = GHASH1 ⊕ E`<sub>`k`</sub>`(y`<sub>`0`</sub>`) = (U1`<sub>`0`</sub>` ⨂ H`<sup>`3`</sup>`) ⊕ (U1`<sub>`1`</sub>` ⨂ H`<sup>`2`</sup>`) ⊕ (U1`<sub>`2`</sub>` ⨂ H) ⊕ E`<sub>`k`</sub>`(y`<sub>`0`</sub>`)`.

The formula for the second tag `T2` is similar:

`T2 = GHASH2 ⊕ E`<sub>`k`</sub>`(y`<sub>`0`</sub>`) = (U2`<sub>`0`</sub>` ⨂ H`<sup>`3`</sup>`) ⊕ (U2`<sub>`1`</sub>` ⨂ H`<sup>`2`</sup>`) ⊕ (U2`<sub>`2`</sub>` ⨂ H) ⊕ E`<sub>`k`</sub>`(y`<sub>`0`</sub>`)`.

Notice how in both formulas `E`<sub>`k`</sub>`(y`<sub>`0`</sub>`)` appears. This is the crucial part. Remember that `E`<sub>`k`</sub>`(y`<sub>`0`</sub>`)` is the encryption of the `Y`<sub>`0`</sub> block using the AES key. The `Y`<sub>`0`</sub> block is only dependant on the nonce, which we assume to have been the same in both messages, and of course we assume both messages were encrypted with the same key. This means that `E`<sub>`k`</sub>`(y`<sub>`0`</sub>`)` is exactly the same value in both tags. This means that `E`<sub>`k`</sub>`(y`<sub>`0`</sub>`)` can be cancelled out by adding the two equations together:

`T1 ⊕ T2 = ((U1`<sub>`0`</sub>` ⨂ H`<sup>`3`</sup>`) ⊕ (U1`<sub>`1`</sub>` ⨂ H`<sup>`2`</sup>`) ⊕ (U1`<sub>`2`</sub>` ⨂ H) ⊕ E`<sub>`k`</sub>`(y`<sub>`0`</sub>`)) ⊕ ((U2`<sub>`0`</sub>` ⨂ H`<sup>`3`</sup>`) ⊕ (U2`<sub>`1`</sub>` ⨂ H`<sup>`2`</sup>`) ⊕ (U2`<sub>`2`</sub>` ⨂ H) ⊕ E`<sub>`k`</sub>`(y`<sub>`0`</sub>`))` <br/>
`=  ((U1`<sub>`0`</sub>` ⊕ U2`<sub>`0`</sub>`) ⨂ H`<sup>`4`</sup>`) ⊕ ((U1`<sub>`1`</sub>` ⊕ U2`<sub>`1`</sub>`) ⨂ H`<sup>`2`</sup>`) ⊕ ((U1`<sub>`2`</sub>` ⊕ U2`<sub>`2`</sub>`) ⨂ H)`.

By adding the two equations together, we have completely eliminated `E`<sub>`k`</sub>`(y`<sub>`0`</sub>`)`. We'll now look at what's left in this formula, and how we can use it to recover `H`.

Rearraning the formula by adding `T1 ⊕ T2` on both sides gives us a zero on one side of the equation:

`0 = ((U1`<sub>`0`</sub>` ⊕ U2`<sub>`0`</sub>`) ⨂ H`<sup>`4`</sup>`) ⊕ ((U1`<sub>`1`</sub>` ⊕ U2`<sub>`1`</sub>`) ⨂ H`<sup>`2`</sup>`) ⊕ ((U1`<sub>`2`</sub>` ⊕ U2`<sub>`2`</sub>`) ⨂ H) ⊕  T1 ⊕ T2`

Now, you might notice, this is _extremely_ similar to a polynomial equation. In fact, it is a polynomial equation for `H`! Forget for a moment that `H` and all the `U` values are in `GF(2`<sup>`128`</sup>`)` and think of any other polynomial equation you might have seen, like `4x`<sup>`4`</sup>` + 2x`<sup>`3`</sup>` + 3x`<sup>`2`</sup>` + 7x + 1 = 0`. This is exactly the same, just with `H` instead of `x` and with coefficients the coefficients `U1`<sub>`i`</sub>` ⊕ U2`<sub>`i`</sub> instead of a regular real number like `4`. 

Note that attacker that has obtained both transmitted messages has knowledge of `T1`, `T2` as well as `U1` and `U2`, as the tag and ciphetext (with associated data) are the "public" parts of the AES-GCM scheme. So, because an attacker has knowledge of `U1` and `U2`, we can treat this coefficient like any other constant coefficient in a polynomial equation. We've already defined the addition and multiplication operations in `GF(2`<sup>`128`</sup>`)`, so hopefully it becomes clear that we can treat the formula we just derived like any other polynomial equation.

If we can find a solution for this polynomial equation, we can recover the `H` value. Why is this interesting? Remember that `H` is the `GHASH` key, which is derived from the AES key. If we can recover `H`, we can use it to compute the `GHASH` function for any data we want. This means that we can authenticate any data we want, even if we don't know the AES key. Combined with the keystream recovery demonstrated early, this leads to a **_full break_** of the AES-GCM encryption scheme.

### Solving the polynomial equation

So, the question is, how do we solve this polynomial equation? This is where the Cantor-Zassenhaus algorithm comes in. The Cantor-Zassenhaus algorithm is an algorithm that can be used to factor polynomials specifically over finite fields. In our case, we want to factor the polynomial equation we derived earlier over `GF(2`<sup>`128`</sup>`)`. The Cantor-Zassenhaus algorithm is a probabilistic algorithm, which means that it might not always find a solution, but given enough attempts, it will find a solution with an arbitrarily high probability.

The Cantor-Zassenhaus algorithm cannot be applied to just any polynomial equation, there are a few requirements that must be ticked off before the algorithm can be used. Lukily, there exist other algorithms to ensure that these requirements are met for any given polynomial:

1. The polynomial must be square-free, which means that it has no repeated roots. For example, let's say we have a polynomial equation `H ⊕ 1 = 0`. Remember that addition in `GF(2`<sup>`128`</sup>`)` is the XOR operation, so if we set `H` to `1`, then `H ⊕ 1 = 1 ⊕ 1 = 0`. So the polynomial has a root at `H = 1`. If we now multiply this polynomial with itself, we get a new polynomial: `(H ⊕ 1) ⨂ (H ⊕ 1) = H`<sup>`2`</sup>` ⊕ 1`. This polynomial has a repeated root at `H = 1`, because `H ⊕ 1` appears twice in the factorization of the polynomial. You can also think of this as the polynomial having a factor `(H ⊕ 1)` squared. The Cantor-Zassenhaus algorithm cannot factor polynomials with repeated roots, so we need to make sure that the polynomial we derived earlier does not have any repeated roots, which is the case when it is "square-free". To achive this requirement, we will be constructing a new polynomial that contains all the factors of the original polynomial exactly once. Although this algorithm changes the "form" of the polynomial, the values of the roots stay unchanged, only their multiplicity (how often they appear) is set to exactly one.

2. The polynomial must be the product of polynomials of equal degrees. For example, take the polynomial equation `H`<sup>`2`</sup>` ⊕ (x ⨂ H) ⊕ 1 = 0`. Here the `x` is the polynomial representation of the block value `40000000000000000000000000000000`, like we discussed earlier. This polynomial has degree `2` and is irreducible, which means that it cannot be factored into two polynomials of degree `1`, which also means it doesn't have any roots. If we multiply this by `H + 1`, we get `H`<sup>`3`</sup>` ⊕ ((x + 1) ⨂ H`<sup>`2`</sup>`) ⊕ ((x + 1) ⨂ H) ⊕ 1`, which is a polynomial of degree `3`. However, this polynomial cannot be factored using the Cantor-Zassenhaus algorithm because it is the product of one polynomial of degree `2` and one polynomial of degree `1`. We need to split the input polynomial its "parts", so into a list of polynomials that only have factors of the same degree. This is called "distinct-degree factorization". It is the last step needed before we can then apply the Cantor-Zassenhaus algorithm to find the roots of each of the "equal-degree" polynomials.

The algorithms to make the polynomial square-free and to split it into polynomials of equal degrees are well-documented and there's even pseudocode available on Wikipedia for [square-free factorization](https://en.wikipedia.org/wiki/Factorization_of_polynomials_over_finite_fields#Square-free_factorization) and [distinct-degree factorization](https://en.wikipedia.org/wiki/Factorization_of_polynomials_over_finite_fields#Distinct-degree_factorization) respectively.

Once we have a square-free polynomial that is the product of polynomials of equal degrees, we can use the Cantor-Zassenhaus algorithm to split the polynomial into two factors and do so repeatedly until we have found all the factors.

I'll outline the main idea of the Cantor-Zassenhaus algorithm here, but again, you can find [pseudocode on Wikipedia](https://en.wikipedia.org/wiki/Factorization_of_polynomials_over_finite_fields#Cantor%E2%80%93Zassenhaus_algorithm)[^3]. We want to factor a polynomial `f` into two factors. This assumes we already have a square-free polynomial and that it is the product of polynomials of equal degrees `d`. For polynomials in `GF(2`<sup>`128`</sup>`)`, the algorithm works as follows:

[^3]: Note however that the pseudocode in Wikipedia is for odd-characteristic fields. For `GF(2`<sup>`128`</sup>`)`, we need to raise the the random polynomial `h` to the power of `⅓ ⋅ (2`<sup>`d ⋅ 128`</sup>`) - 1`, instead of `½`.

1. Pick a random polynomial `h` of degree less than `f` and compute the greatest common divisor of `f` and `h`.
2. Set `M = ⅓(2`<sup>`d ⋅ 128`</sup>` - 1)` and compute the greatest common denominator of `h`<sup>`M`</sup>` - 1` and `f`. We'll call this `g`.
3. If `g` is not `1` or `f` (which are both trivial factors that we don't care about), we have found a non-trivial factor of `f`. We can then recursively factor `g` and `f / g` to find all the factors of `f`.
4. If `g` is `1` or `f`, we need to pick a new random polynomial `h` and try again.

By just repeatedly picking a random polynomial, raising it to the power of `⅓ ⋅ (2`<sup>`d ⋅ 128`</sup>`) - 1`, and computing the greatest common divisor with the polynomial we want to factor, we can find all the factors of the polynomial. But you might spot a problem: Raising a polynomial to the power of `⅓ ⋅ (2`<sup>`d ⋅ 128`</sup>`) - 1` seems almost impossible, because that number is absolutely huge! But, of course, there's a trick: Instead of raising the polynomial to the power of `⅓ ⋅ (2`<sup>`d ⋅ 128`</sup>`) - 1`, and then computing the greatest common denominator immediately, we can reduce the polynomial by `f` before computing the greatest common denominator, without "losing" any factors. Calculating an almost arbitrarily large power with a given modulus is a well-known problem in computer algebra, and the square-and-multiply algorithm can be used to compute the result efficiently. Without this trick, the Cantor-Zassenhaus algorithm would be infeasible for polynomials of degree `128` in `GF(2`<sup>`128`</sup>`)` and it is one of the core reasons why the Cantor-Zassenhaus algorithm is so powerful.

Once we have found all the factors of the polynomial, we look at all the factors with degree `1`. These are the factors that are linear polynomials, so they are of the form `H + a` where `a` is a constant. We then know that when we set `H = a`, this linear polynomial will evaluate to zero, and is thus is a solution to the polynomial equation we derived earlier. Note that we might have multiple solutions for `H` if there are multiple roots to the polynomial but only one of them is the correct `H` used in the `GHASH` computation, which we will need to use if we want to authenticate other data. To do this, we need a third message that was authenticated using the same key and nonce. We can then use the recovered `H` to compute the `GHASH` function for the third message and check if the result of our computation matches the real authentication tag of the third message. If it does, we have successfully recovered the `H` value and can now authenticate any data we want.

### Putting it all together

We now have all the pieces we need to recover the `GHASH` key `H` if the nonce is reused. We can use the Cantor-Zassenhaus algorithm to factor the polynomial equation we derived earlier and recover the `H` value. We can then use the recovered `H` to compute the `GHASH` function for any data we want and authenticate it. Let's see it all in action!

First, we need to simulate the nonce reuse. For simplicity, we'll ignore the associated data because it doesn't affect the attack, it just means we have to take the associated data into account when constructing the polynomial equation. Enter a key, nonce and three plaintexts to compute the ciphertexts and the authentication tags[^cheating]:

[^cheating]: To prove that I am not cheating, you may omit the key entirely. You can use [CyberChef](https://gchq.github.io/CyberChef/#recipe=AES_Encrypt(%7B'option':'Hex','string':'000102030405060708090a0b0c0d0e0f'%7D,%7B'option':'Hex','string':'deadbeefcafeaffebadbabe0'%7D,'GCM','Hex','Hex',%7B'option':'Hex','string':''%7D)&input=YWJhZGlkZWEwMDExMjIzMzQ0NTU2Njc3ODg5OQ) to calculate the ciphertext and tag for any plaintext you wish. First, choose a random key and nonce (CyberChef calls this an IV). You can then delete the key from the field below, and copy over the nonce. Then, enter three random plaintexts and copy the plaintext, ciphertext and tags into the fields below. I'll still be able to recover the `H` key, without even having access to the key at all.

<p id="demo-nonce-reuse-1">
<noscript><strong>You have JavaScript disabled! Although you will be able to read the content, the widgets will not work. Please consider enabling JavaScript. There is no tracking or anything on this site, it'll just be used to render these widgets.</strong></noscript>
</p>
<script type="module">
    import { aes_gcm_widget } from "/js/aesgcm_widgets.js";
    aes_gcm_widget(document.getElementById("demo-nonce-reuse-1"), "abad1dea00abad1dea00abad1dea00abad1dea00abad1dea", "1", false);
</script>
<p id="demo-nonce-reuse-2"></p>
<script type="module">
    import { aes_gcm_widget } from "/js/aesgcm_widgets.js";
    aes_gcm_widget(document.getElementById("demo-nonce-reuse-2"), "01234567890123456789012345678901234567890123456789", "2", true);
</script>
<p id="demo-nonce-reuse-3"></p>
<script type="module">
    import { aes_gcm_widget } from "/js/aesgcm_widgets.js";
    aes_gcm_widget(document.getElementById("demo-nonce-reuse-3"), "1deadbeef11deadbeef11deadbeef11deadbeef11deadbeef1", "3", true);
</script>

Now that we have the ciphertexts and the authentication tags for three messages that were encrypted using the same key and nonce, we can recover candidate `H` values by solving the polynomial equation we derived earlier and then verify the correct `H` value by computing the `GHASH` function for the third message if more than one `H` solves the equation.

We'll need to figure out the polynomial equation to solve. Let's split up the first ciphertext into their respective blocks and XOR them together to get the coefficients of the polynomial equation:

<p id="demo-nonce-reuse-construct-polynomial"></p>
<script type="module">
    import { construct_polynomial_widget } from "/js/aesgcm_widgets.js";
    construct_polynomial_widget(document.getElementById("demo-nonce-reuse-construct-polynomial"));
</script>

Now, we can solve this equation to get candidate `H` values, one of which is the real `H` key used during AES-GCM authentication.

<p id="demo-nonce-reuse-h-candidates"></p>
<script type="module">
    import { h_candidates_widget } from "/js/aesgcm_widgets.js";
    h_candidates_widget(document.getElementById("demo-nonce-reuse-h-candidates"));
</script>

We have just used the Cantor-Zassenhaus algorithm to recover the `H` key and `E`<sub>`k`</sub>`(y`<sub>`0`</sub>`)` value used during the AES-GCM authentication, which lets us authenticate **any message we want**.

### Recap

Although more complicated than the keystream recovery, when a nonce is reused, we can use polynomial factorization to figure out the `H` key, which ultimately let's us authenticate any data we want. So, in total, the attack goes like this:

1. Alice and Bob agree to a secret shared key. This key is unknown to the attacker.
1. Alice sends Bob a secret message, encrypted using AES-GCM. We assume that the attacker knows the plaintext that Alice sent, and records the nonce, ciphertext and tag transmitted by Alice to Bob.
1. Bob is able to use the nonce and tag to authenticate the ciphertext, and uses the shared key to decrypt the ciphertext.
1. Alice sends Bob two more messages, all encrypted using the *same nonce*. The attacker can use the first plaintext/ciphertext pair to recover the keystream, and thus recover the plaintext for these messages as well.
1. Bob, again, is able to use the nonce and tag to authenticate the ciphertext, and decrypt it using the shared key.
1. The attacker has recovered the keystream by XORing the first plaintext with the ciphertext.
1. The attacker uses the polynomial factorization to recover the `H` and `E`<sub>`k`</sub>`(y`<sub>`0`</sub>`)` values.
1. The attacker uses these values to construct a message and sends the message to Bob.
1. Bob successfully authenticates the ciphertext, even though the ciphertext wasn't sent by Alice. Because the keystream is the same as well, Bob is also able to decrypt the ciphertext. This means that Bob has now received a message from the attacker that they think was sent by Alice.

## Conclusion

Thank you for reading all the way through this huge post! I hope I was able to explain AES-GCM well enough and that you've got a good feel for why resuing a nonce with AES-GCM is such a big deal.

If you're interested, the code powering all the interactive widgets here is on GitHub. The factorization algorithms were implemented in [Rust and built for WebAssembly](https://github.com/frereit/frereit.github.io/blob/cantor_zassenhaus/wasm/cantor-zassenhaus/src/factorize.rs) and all the DOM manipulation and reactiveness was done manually in a [1200 line JavaScript file 😭](https://github.com/frereit/frereit.github.io/blob/cantor_zassenhaus/static/js/aesgcm_widgets.js).

This blog post was an enormous amount of work, but I hope it was worth it. If you have any questions, comments, or feedback, please don't hesitate to reach out to me on [Mastodon](https://infosec.exchange/@fre), I'd love to here from you! Also, if you'd like to send some donation my way, don't. Instead send some feedback my way and some money to the [Electronic Frontier Foundation](https://supporters.eff.org/donate/), [The Internet Archive](https://archive.org/donate) or anything, really, that you think is important. Thanks again for reading!

## Addendum: Using SageMath to do the heavy lifting

In this blog post, I've shown how the square free factorization, the distinct degree factorization, and the Cantor-Zassenhaus algorithms can be used to break AES-GCM. To be able to show you the internals right in your browser, I've implemented the algorithms from scratch in [Rust](https://github.com/frereit/frereit.github.io/blob/cantor_zassenhaus/wasm/cantor-zassenhaus/src/factorize.rs) but if you actually want to execute this attack in real life, you can use [SageMath](https://www.sagemath.org/) to calculate the roots of the polynomial, instead of implementing the algorithms yourself.

First, setup the `GF(2`<sup>`128`</sup>`)` field:

```
>>> F.<a> = GF(2)[]
>>> F.<x> = GF(2^128, modulus=a^128 + a^7 + a^2 + a + 1)
```

Then, construct a polynomial ring over this field:

```
>>> R.<H> = PolynomialRing(F)
```

If we now want to find the roots of the polynomial `H`<sup>`2`</sup>` + H + 1`, we can use the `.roots()` method:

```
>>> (H^2 + H + 1).roots()
[(x^125 + x^123 + x^120 + x^118 + x^116 + x^115 + x^113 + x^111 + x^110 + x^103 + x^101 + x^100 + x^96 + x^95 + x^94 + x^93 + x^92 + x^90 + x^86 + x^85 + x^84 + x^81 + x^80 + x^76 + x^75 + x^73 + x^71 + x^70 + x^69 + x^68 + x^67 + x^64 + x^62 + x^61 + x^58 + x^57 + x^56 + x^54 + x^53 + x^51 + x^49 + x^47 + x^45 + x^43 + x^42 + x^39 + x^36 + x^35 + x^34 + x^33 + x^32 + x^31 + x^29 + x^26 + x^23 + x^21 + x^20 + x^17 + x^11 + x^9 + x^8 + x^3,
  1),
 (x^125 + x^123 + x^120 + x^118 + x^116 + x^115 + x^113 + x^111 + x^110 + x^103 + x^101 + x^100 + x^96 + x^95 + x^94 + x^93 + x^92 + x^90 + x^86 + x^85 + x^84 + x^81 + x^80 + x^76 + x^75 + x^73 + x^71 + x^70 + x^69 + x^68 + x^67 + x^64 + x^62 + x^61 + x^58 + x^57 + x^56 + x^54 + x^53 + x^51 + x^49 + x^47 + x^45 + x^43 + x^42 + x^39 + x^36 + x^35 + x^34 + x^33 + x^32 + x^31 + x^29 + x^26 + x^23 + x^21 + x^20 + x^17 + x^11 + x^9 + x^8 + x^3 + 1,
  1)]
```

This immediately gives us the candidate values for `H`, no need to jump through any extra hoops. I'll leave implementing the whole attack in SageMath as an exercise to the reader ;).

<script type="module">
    import { register_synced_inputs } from "/js/input_sync.js";
    register_synced_inputs();
</script>
<script>
    // https://bugzilla.mozilla.org/show_bug.cgi?id=1901414
    if (navigator.userAgent.indexOf("Firefox") != -1) {
        let imgs = document.getElementsByTagName("img");
        for (let i = 0; i < imgs.length; i++) {
            imgs[i].onload = () => {
                setTimeout(() => {
                    imgs[i].style.width = imgs[i].dataset.ffwidth;
                }, 100);
            }
        }
    }
</script>