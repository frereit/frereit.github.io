// https://stackoverflow.com/a/50868276 START
const fromHexString = (hexString) => {
    if (hexString.length == 0) {
        return new Uint8Array(0);
    }

    // make sure the hex string has an even length and contains only valid hex characters
    if (hexString.length % 2 != 0 || /[^0-9a-f]/i.test(hexString)) {
        throw new Error('Invalid hex string');
    }
    return Uint8Array.from(hexString.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
}

const toHexString = (bytes) => {
    if (bytes.length == 0) {
        return "";
    }
    return bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');
}
// https://stackoverflow.com/a/50868276 END

class F128Element {
    constructor(value) {
        if (typeof value === "number") {
            throw new Error("value has to be a BigInt");
        }
        this.value = value;
    }

    inverse() {
       return this.pow(BigInt("0xfffffffffffffffffffffffffffffffd"));
    }

    reduce() {
        let value = this.value;
        while (value >= (BigInt(1) << BigInt(128))) {
            let reduction_polynomial = BigInt("0x100000000000000000000000000000087");
            while (value >= (reduction_polynomial << BigInt(1))) {
                reduction_polynomial = reduction_polynomial << BigInt(1);
            }
            value ^= reduction_polynomial;
        }
        return new F128Element(value);
    }

    degree() {
        let value = this.value;
        let degree = -1;
        while (value) {
            value = value >> BigInt(1);
            degree++;
        }
        return degree;
    }

    toString() {
        const exponents = this.to_exponents();
        let string = "";
        if (exponents.length === 0) {
            return "0";
        }
        exponents.reverse();
        for (const exponent of exponents) {
            if (exponent == 0) {
                string += "1 + ";
            } else if (exponent == 1) {
                string += "x + ";
            } else {
                string += "x^" + exponent + " + ";
            }
        }
        return string.slice(0, -3);
    }

    static from_string(input) /* : F128Element */ {
        let string = input.trim();
        // Check if the string is in the correct format
        if (!/^((x\^([2-9]|[1-9]\d|1[01]\d|12[0-7]))|x|1|0)(\s*\+\s*((x\^([2-9]|[1-9]\d|1[01]\d|12[0-7]))|x|1|0))*$/.test(string)) {
            throw new Error('Invalid format');
        }

        if (string == "0") {
            return new F128Element(BigInt(0));
        }

        let exponents = [];
        let terms = string.split("+");
        for (const term_unstripped of terms) {
            let term = term_unstripped.trim();
            if (term == "1") {
                exponents.push(0);
            } else if (term == "0") {
                continue;
            } else if (term == "x") {
                exponents.push(1);
            } else {
                exponents.push(Number(term.slice(2)));
            }
        }
        // remove all elements that appear an even number of times
        let exponents_set = new Set(exponents);
        for (const exponent of exponents_set) {
            let count = exponents.filter(e => e === exponent).length;
            if (count % 2 == 0) {
                exponents = exponents.filter(e => e !== exponent);
            }
        }
        return F128Element.from_exponents(exponents);
    }

    static random() /* : F128Element */ {
    let value = BigInt(0);
    for (let i = 0; i < 128; i++) {
        if (Math.random() < 0.5) {
            value |= BigInt(1) << BigInt(i);
        }
    }
    return new F128Element(value);
}

    static from_block(block /* Uint8Array */) /* : F128Element */ {
    let value = BigInt(0);
    for (let i = 0; i < 128; i++) {
        const byte_index = Math.floor(i / 8);
        const bit_index = 7 - (i % 8);
        if (block[byte_index] & (1 << bit_index)) {
            value |= BigInt(1) << BigInt(i);
        }
    }
    return new F128Element(value);
}

    static from_exponents(exponents /* number[] */) /* : F128Element */ {
    let value = BigInt(0);
    for (const exponent of exponents) {
        value |= BigInt(1) << BigInt(exponent);
    }
    return new F128Element(value);
}

to_block() /* : Uint8Array */ {
    let block = new Uint8Array(16);
    for (let i = 0; i < 128; i++) {
        const byte_index = Math.floor(i / 8);
        const bit_index = 7 - (i % 8);
        if (this.value & (BigInt(1) << BigInt(i))) {
            block[byte_index] |= 1 << bit_index;
        }
    }
    return block;
}

to_exponents() /* : number[] */ {
    let exponents = [];
    let i = 0;
    while (this.value >= (BigInt(1) << BigInt(i))) {
        if (this.value & (BigInt(1) << BigInt(i))) {
            exponents.push(i);
        }
        i++;
    }
    return exponents;
}

equals(other) {
    return this.value === other.value;
}

add(other) {
    return new F128Element(this.value ^ other.value);
}

sub(other) {
    return new F128Element(this.value ^ other.value);
}

mul(other) {
    let result = BigInt(0);
    let a_factor = this.value;
    let b_factor = other.value;
    while (a_factor && b_factor) {
        if (b_factor & BigInt(1)) {
            result ^= a_factor;
        }
        a_factor = a_factor << BigInt(1);
        if (a_factor >> BigInt(128)) {
            a_factor ^= BigInt("0x100000000000000000000000000000087");
        }
        b_factor = b_factor >> BigInt(1);
    }
    return new F128Element(result);
}

mul_unreduced(other) {
    let result = BigInt(0);
    let a_factor = this.value;
    let b_factor = other.value;
    while (a_factor && b_factor) {
        if (b_factor & BigInt(1)) {
            result ^= a_factor;
        }
        a_factor = a_factor << BigInt(1);
        b_factor = b_factor >> BigInt(1);
    }
    return new F128Element(result);
}

pow(exponent) {
    let result = new F128Element(BigInt(1));
    let base = this;
    while (exponent) {
        if (exponent & BigInt(1)) {
            result = result.mul(base);
        }
        base = base.mul(base);
        exponent = exponent >> BigInt(1);
    }
    return result;
}
}

class GHASH {
    constructor(associated_data, auth_key) {
        this.auth_key = F128Element.from_block(auth_key);
        this.auth_tag = new F128Element(BigInt(0));
        this.associated_data_bitlength = BigInt(8 * associated_data.length);
        this.finalized = false;
        this.ciphertext_buffer = new Uint8Array();
        this.ciphertext_bitlength = BigInt(0);

        // Add the associated data to the auth_tag.
        this.update(associated_data);
        this.pad_current_block();

        // We have to clear the buffer and bitlength because we don't want to count the associated data
        // in the ciphertext bitlength.
        this.ciphertext_bitlength = BigInt(0);
        this.ciphertext_buffer = new Uint8Array();
    }

    update(data) {
        if (this.finalized) {
            throw new Error("GHASH is already finalized");
        }
        let new_buffer = new Uint8Array(this.ciphertext_buffer.length + data.length);
        new_buffer.set(this.ciphertext_buffer, 0);
        new_buffer.set(data, this.ciphertext_buffer.length);
        this.ciphertext_buffer = new_buffer;
        while (this.ciphertext_buffer.length >= 16) {
            let block = this.ciphertext_buffer.slice(0, 16);
            this.ciphertext_buffer = this.ciphertext_buffer.slice(16);
            this.auth_tag = this.auth_tag.add(F128Element.from_block(block));
            this.auth_tag = this.auth_tag.mul(this.auth_key);
            this.ciphertext_bitlength += BigInt(8 * block.length);
        }
    }

    pad_current_block() {
        const padding_length = 16 - this.ciphertext_buffer.length;
        if (padding_length == 16) {
            return;
        }
        let padding = new Uint8Array(padding_length);
        this.update(padding);
        this.ciphertext_bitlength -= BigInt(8 * padding_length); // We don't want to count the padding.
    }

    finalize() {
        if (this.finalized) {
            throw new Error("GHASH is already finalized");
        }
        this.pad_current_block();
        let bitlength_buffer = new Uint8Array(16);
        let view = new DataView(bitlength_buffer.buffer);
        view.setBigUint64(0, this.associated_data_bitlength, false);
        view.setBigUint64(8, this.ciphertext_bitlength, false);
        this.update(bitlength_buffer);
        this.finalized = true;
        return this.auth_tag.to_block();
    }

    static ghash(ciphertext, associated_data, auth_key) {
        let ghash = new GHASH(associated_data, auth_key);
        ghash.update(ciphertext);
        return ghash.finalize();
    }
}

class AESGCM {
    /// WARNING: This class is not secure and should not be used for anything except this demo.
    /// It is only here to demonstrate the AES-GCM encryption process.
    /// IT CANNOT BE MADE SECURE. DO NOT TRY.
    /// IF YOU WANT TO USE AES-GCM, USE THE WEB CRYPTO API.
    static async new(key, nonce, associated_data) {
        // UGLY but we want an async constructor.
        let aes_gcm = new AESGCM();
        aes_gcm.key = await crypto.subtle.importKey(
            "raw",
            key.buffer,
            "AES-CBC",
            true,
            ["encrypt", "decrypt"],
        );
        aes_gcm.y = 1;
        aes_gcm.h = await aes_gcm.raw_aes(new Uint8Array(16));
        aes_gcm.keystream = new Uint8Array();
        aes_gcm.ghash = new GHASH(associated_data, aes_gcm.h);

        if (nonce.length == 12) {
            aes_gcm.y0 = new Uint8Array(16);
            aes_gcm.y0.set(nonce);
            aes_gcm.y0[15] = 1;
        } else {
            aes_gcm.y0 = GHASH.ghash(nonce, new Uint8Array(), aes_gcm.h);
        }

        return aes_gcm;
    }

    y_block(index) {
        let block = new Uint8Array(16);
        block.set(this.y0);
        let view = new DataView(block.buffer);
        let val = view.getUint32(12, false);
        view.setUint32(12, val + index, false);
        return block;
    }

    async update(plaintext) {
        let ciphertext = new Uint8Array(plaintext.length);
        for (const [i, byte] of plaintext.entries()) {
            if (this.keystream.length == 0) {
                this.keystream = await this.raw_aes(this.y_block(this.y));
                this.y++;
            }
            ciphertext[i] = byte ^ this.keystream[0];
            this.keystream = this.keystream.slice(1);
        }
        this.ghash.update(ciphertext);
        return ciphertext;
    }

    async finalize() {
        let auth_tag = this.ghash.finalize();
        let auth_tag_mask = await this.raw_aes(this.y_block(0));
        let auth_tag_block = new Uint8Array(16);
        for (let i = 0; i < 16; i++) {
            auth_tag_block[i] = auth_tag[i] ^ auth_tag_mask[i];
        }
        return auth_tag_block;
    }

    static async encrypt(key, nonce, associated_data, plaintext) {
        let aes_gcm = await AESGCM.new(key, nonce, associated_data);
        let ciphertext = await aes_gcm.update(plaintext);
        return {
            ciphertext,
            auth_tag: await aes_gcm.finalize(),
        };
    }

    static async decrypt(key, nonce, associated_data, ciphertext, auth_tag) {
        let aes_gcm = await AESGCM.new(key, nonce, associated_data);
        let plaintext = await aes_gcm.update(ciphertext);
        let { auth_tag: own_auth_tag } = await AESGCM.encrypt(key, nonce, associated_data, plaintext);
        if (toHexString(own_auth_tag) != toHexString(auth_tag)) {
            throw new Error("auth_tag is " + toHexString(auth_tag) + " but should be " + toHexString(own_auth_tag));
        }
        return plaintext;
    }

    async raw_aes(block) {
        // WARNING:
        // NEVER EVER use this function FOR ANYTHING except this demo.
        // IT IS NOT SECURE AND CANNOT BE MADE SECURE.
        // It is only here to demonstrate the AES-GCM encryption process.
        if (!this.key) {
            throw new Error("key not loaded");
        }
        if (block.length != 16) {
            throw new Error("block has to be a 16-byte Uint8Array");
        }
        let encrypted = await crypto.subtle.encrypt(
            {
                name: "AES-CBC",
                iv: new Uint8Array(16), // Explicitly set the IV to 0, so that we get the raw AES encryption
            },
            this.key,
            block,
        )
        // IV was 0, so the first block is just AES(key, block).
        // We just discard the second block. It is the PKCS#7 padding block.
        return new Uint8Array(encrypted.slice(0, 16));
    }

    async raw_aes_inverse(block) {
        // We use the key to encrypt a PKCS#7 padding block and then XOR it with the block,
        // so that we can do AES-128-CBC decryption with an IV of 0 and get the raw AES decryption.
        if (!this.key) {
            throw new Error("key not loaded");
        }
        if (block.length != 16) {
            throw new Error("block has to be a 16-byte Uint8Array");
        }
        let padding_block = new Uint8Array(16);
        padding_block.fill(16); // PKCS#7 padding block

        let encrypted = new Uint8Array((await crypto.subtle.encrypt(
            {
                name: "AES-CBC",
                iv: block, // PKCS#7 padding block is XORed with the last block in "decryption"
            },
            this.key,
            padding_block,
        )).slice(0, 16));

        let fake_cbc = new Uint8Array(32);
        fake_cbc.set(block);
        fake_cbc.set(encrypted, 16);

        let decrypted = await crypto.subtle.decrypt(
            {
                name: "AES-CBC",
                iv: new Uint8Array(16), // IV is 0, so we get the raw AES decryption
            },
            this.key,
            fake_cbc,
        )
        return new Uint8Array(decrypted);
    }

    static async raw_aes(key, block) {
        let cryptor = await AESGCM.new(key, new Uint8Array(12), new Uint8Array());
        return await cryptor.raw_aes(block);
    }

    static async raw_aes_inverse(key, block) {
        let cryptor = await AESGCM.new(key, new Uint8Array(12), new Uint8Array());
        return await cryptor.raw_aes_inverse(block);
    }
}

async function test_counter_mode_block_generator_with_12_byte_nonce() {
    let key = new Uint8Array(16);
    let nonce = fromHexString("aa1d5a0aa1ea09f6ff91e534");
    let aes_gcm = await AESGCM.new(key, nonce, new Uint8Array());
    let y0 = toHexString(aes_gcm.y_block(0));
    if (y0 != "aa1d5a0aa1ea09f6ff91e53400000001") {
        throw new Error("y_block(0) is " + y0);
    }
    let y1 = toHexString(aes_gcm.y_block(1));
    if (y1 != "aa1d5a0aa1ea09f6ff91e53400000002") {
        throw new Error("y_block(1) is " + y1);
    }
    let yc478 = toHexString(aes_gcm.y_block(0xc478));
    if (yc478 != "aa1d5a0aa1ea09f6ff91e5340000c479") {
        throw new Error("y_block(0xc478) is " + yc478);
    }
    console.log("test_counter_mode_block_generator_with_12_byte_nonce passed");
}

async function test_counter_mode_block_generator_with_8_byte_nonce() {
    let key = fromHexString("feffe9928665731c6d6a8f9467308308");
    let nonce = fromHexString("cafebabefacedbad");
    let aes_gcm = await AESGCM.new(key, nonce, new Uint8Array());
    let y0 = toHexString(aes_gcm.y_block(0));
    if (y0 != "c43a83c4c4badec4354ca984db252f7d") {
        throw new Error("y_block(0) is " + y0);
    }
    let y1 = toHexString(aes_gcm.y_block(1));
    if (y1 != "c43a83c4c4badec4354ca984db252f7e") {
        throw new Error("y_block(1) is " + y1);
    }
    console.log("test_counter_mode_block_generator_with_8_byte_nonce passed");
}

async function test_aes_gcm() {
    const testcases = [
        {
            "key": "feffe9928665731c6d6a8f9467308308",
            "plaintext": "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
            "nonce": "cafebabefacedbaddecaf888",
            "associated_data": "",
            "ciphertext": "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
            "auth_tag": "4d5c2af327cd64a62cf35abd2ba6fab4",
            "filename": "nist_3"
        },
        {
            "key": "feffe9928665731c6d6a8f9467308308",
            "plaintext": "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
            "nonce": "cafebabefacedbaddecaf888",
            "associated_data": "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            "ciphertext": "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
            "auth_tag": "5bc94fbc3221a5db94fae95ae7121a47",
            "filename": "nist_4"
        },
        {
            "key": "feffe9928665731c6d6a8f9467308308",
            "plaintext": "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
            "nonce": "cafebabefacedbad",
            "associated_data": "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            "ciphertext": "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598",
            "auth_tag": "3612d2e79e3b0785561be14aaca2fccb",
            "filename": "nist_5"
        },
        {
            "key": "00000000000000000000000000000000",
            "plaintext": "00000000000000000000000000000000",
            "nonce": "000000000000000000000000",
            "associated_data": "",
            "ciphertext": "0388dace60b6a392f328c2b971b2fe78",
            "auth_tag": "ab6e47d42cec13bdf53a67b21257bddf",
            "filename": "nist_2"
        },
        {
            "key": "feffe9928665731c6d6a8f9467308308",
            "plaintext": "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
            "nonce": "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",
            "associated_data": "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            "ciphertext": "8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5",
            "auth_tag": "619cc5aefffe0bfa462af43c1699d050",
            "filename": "nist_6"
        },
        {
            "key": "00000000000000000000000000000000",
            "plaintext": "",
            "nonce": "000000000000000000000000",
            "associated_data": "",
            "ciphertext": "",
            "auth_tag": "58e2fccefa7e3061367f1d57a4e7455a",
            "filename": "nist_1"
        }
    ];
    for (const testcase of testcases) {
        let key = fromHexString(testcase.key);
        let nonce = fromHexString(testcase.nonce);
        let associated_data = fromHexString(testcase.associated_data);
        let plaintext = fromHexString(testcase.plaintext);
        let result = await AESGCM.encrypt(key, nonce, associated_data, plaintext);
        if (toHexString(result.ciphertext) != testcase.ciphertext) {
            console.log("Error on tc " + testcase.filename);
            throw new Error("ciphertext is " + toHexString(result.ciphertext) + " but should be " + testcase.ciphertext);
        }
        if (toHexString(result.auth_tag) != testcase.auth_tag) {
            console.log("Error on tc " + testcase.filename);
            throw new Error("auth_tag is " + toHexString(result.auth_tag) + " but should be " + testcase.auth_tag);
        }
    }
    console.log("test_aes_gcm passed");
}

/*
(() => {
    test_counter_mode_block_generator_with_12_byte_nonce().then(console.log).catch(console.error);
    test_counter_mode_block_generator_with_8_byte_nonce().then(console.log).catch(console.error);
    test_aes_gcm().then(console.log).catch(console.error);
})();
*/

export { AESGCM, GHASH, F128Element, fromHexString, toHexString };