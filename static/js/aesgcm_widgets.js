import { AESGCM, F128Element, GHASH, fromHexString, toHexString } from "./aesgcm.js";
import init, { find_zeros, square_free, distinct_degree } from "../wasm/polyfactor.js";

function add_label(text, elem, grid) {
    let label = document.createElement("label");
    label.innerHTML = "<code>" + text + "</code>:";
    grid.appendChild(label);
    grid.appendChild(elem);

    return { label, elem };
}

function length_block(byte_count) {
    let l = new Uint8Array(16);
    const ct_length = BigInt(byte_count) * BigInt(8);
    for (let i = 0; i < 8; i++) {
        l[15 - i] = Number((ct_length >> BigInt(i * 8)) & BigInt(0xff));
    }
    return l;
}

function arraysEqual(a, b) {
  if (a === b) return true;
  if (a == null || b == null) return false;
  if (a.length !== b.length) return false;
  for (var i = 0; i < a.length; ++i) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function hexPolyToHTML(poly) {
    let equation = "";
    for (let i = 0; i < poly.length; i++) {
        if (poly[i] == "00000000000000000000000000000000") {
            continue;
        }
        let part = "(" + poly[i] + " ⨂ H<sup>" + (poly.length - i - 1) + "</sup>)";
        equation += part + " ⊕ ";
    }

    equation = equation.substring(0, equation.length - 3);
    equation += " = 0";
    return equation;
}

function get_blocks(data) {
    let blocks = [];
    for (let i = 0; i < data.length; i += 16) {
        let block = data.slice(i, i + 16);
        if (block.length < 16) {
            const newblock = new Uint8Array(16);
            newblock.set(block);
            block = newblock;
        }
        blocks.push(block);
    }
    blocks.push(length_block(data.length));
    return blocks;
}

export function raw_aes_widget(container) {
    let mode = "encrypt";
    let key_input = document.createElement("input");
    key_input.id = "aes-key";
    key_input.classList.add("sync-aes-key");
    let plaintext_pre = document.createElement("input");
    let ciphertext_pre = document.createElement("input");

    key_input.classList.add("code");
    plaintext_pre.classList.add("code");
    ciphertext_pre.classList.add("code");

    let grid = document.createElement("div");
    grid.classList.add("input-grid");
    container.appendChild(grid);


    add_label("key", key_input, grid);
    add_label("plaintext", plaintext_pre, grid);
    add_label("ciphertext", ciphertext_pre, grid);

    key_input.value = "000102030405060708090a0b0c0d0e0f";
    plaintext_pre.value = "deadbeefcafeaffebadbabe000000001";

    async function updateCiphertext() {
        mode = "encrypt";
        key_input.classList.remove("error");
        plaintext_pre.classList.remove("error");
        ciphertext_pre.classList.remove("error");
        let key;
        try {
            if (key_input.value.length != 32) {
                ciphertext_pre.value = "Key must be 16 bytes (32 hex digits)!";
                key_input.classList.add("error");
                return;
            }
            key = fromHexString(key_input.value);
        } catch (e) {
            ciphertext_pre.value = "Key must be valid hex!";
            key_input.classList.add("error");
            return;
        }
        let plaintext;
        try {
            if (plaintext_pre.value.length != 32) {
                ciphertext_pre.value = "Plaintext must be 16 bytes (32 hex digits)!";
                plaintext_pre.classList.add("error");
                return;
            }
            plaintext = fromHexString(plaintext_pre.value);
        } catch (e) {
            ciphertext_pre.value = "Plaintext must be valid hex!";
            plaintext_pre.classList.add("error");
            return;
        }
        let ciphertext = await AESGCM.raw_aes(key, plaintext);
        let ciphertext_hex = toHexString(ciphertext);
        ciphertext_pre.value = ciphertext_hex;
    }
    async function updatePlaintext() {
        mode = "decrypt";
        key_input.classList.remove("error");
        plaintext_pre.classList.remove("error");
        ciphertext_pre.classList.remove("error");
        let key;
        try {
            if (key_input.value.length != 32) {
                plaintext_pre.value = "Key must be 16 bytes (32 hex digits)!";
                key_input.classList.add("error");
                return;
            }
            key = fromHexString(key_input.value);
        } catch (e) {
            plaintext_pre.value = "Key must be 16 bytes (32 hex digits)!";
            key_input.classList.add("error");
            return;
        }
        let ciphertext;
        try {
            if (ciphertext_pre.value.length != 32) {
                plaintext_pre.value = "Ciphertext must be 16 bytes (32 hex digits)!";
                ciphertext_pre.classList.add("error");
                return;
            }
            ciphertext = fromHexString(ciphertext_pre.value);
        } catch (e) {
            plaintext_pre.value = "Ciphertext must be valid hex!";
            ciphertext_pre.classList.add("error");
            return;
        }
        let plaintext = await AESGCM.raw_aes_inverse(key, ciphertext);
        let plaintext_hex = toHexString(plaintext);
        plaintext_pre.value = plaintext_hex;
    }
    document.body.addEventListener("sync-aes-key", () => {
        if (mode == "encrypt") {
            updateCiphertext();
        } else {
            updatePlaintext();
        }
    })
    plaintext_pre.addEventListener("input", updateCiphertext);
    ciphertext_pre.addEventListener("input", updatePlaintext);
    updateCiphertext();
}

export function ctr_mode_nonce_reuse_widget(container) {
    let key = document.createElement("input");
    key.classList.add("sync-aes-key");
    let nonce = document.createElement("input");
    nonce.classList.add("sync-nonce");
    nonce.id = "aes-gcm-nonce";
    let p1_input = document.createElement("input");
    let p2_input = document.createElement("input");
    let keystream_output = document.createElement("input");
    let c1_output = document.createElement("input");
    let c2_output = document.createElement("input");
    let c1_xor_p1_output = document.createElement("input");
    let c2_xor_c1_xor_p1_output = document.createElement("input");
    keystream_output.disabled = true;
    c1_output.disabled = true;
    c2_output.disabled = true;
    c1_xor_p1_output.disabled = true;
    c2_xor_c1_xor_p1_output.disabled = true;
    key.classList.add("code");
    nonce.classList.add("code");
    p1_input.classList.add("code");
    p2_input.classList.add("code");
    keystream_output.classList.add("code");
    c1_output.classList.add("code");
    c2_output.classList.add("code");
    c1_xor_p1_output.classList.add("code");
    c2_xor_c1_xor_p1_output.classList.add("code");

    nonce.value = "deadbeefcafeaffebadbabe0";
    p1_input.value = "cafeaffe";
    p2_input.value = "badbabe0";

    let grid = document.createElement("div");
    grid.classList.add("input-grid");
    container.appendChild(grid);

    add_label("key", key, grid);
    add_label("nonce", nonce, grid);
    add_label("keystream", keystream_output, grid);

    let p1 = document.createElement("p");
    p1.innerHTML = "Then we encrypt two plaintexts <code>p1</code> and <code>p2</code> by XORing them with the <code>keystream</code>, which gives us <code>c1</code> and <code>c2</code>:";
    p1.setAttribute("style", "grid-column: 1 / span 2");
    grid.appendChild(p1);

    add_label("p1", p1_input, grid);
    add_label("p2", p2_input, grid);
    add_label("c1", c1_output, grid);
    add_label("c2", c2_output, grid);

    let p2 = document.createElement("p");
    p2.innerHTML = "If an attacker now gets hold of <code>c1</code> and <code>p1</code> and wants to decrypt <code>c2</code>, they can use <code>c1 ⊕ p1</code> to calculate the <code>keystream</code> and then use it to decrypt <code>c2</code> without knowing the key:";
    p2.setAttribute("style", "grid-column: 1 / span 2");
    grid.appendChild(p2);

    add_label("c1 ⊕ p1", c1_xor_p1_output, grid);
    add_label("c2 ⊕ c1 ⊕ p1", c2_xor_c1_xor_p1_output, grid);

    let key_input = document.getElementById("aes-key");

    async function update() {
        let nonce_bytes;
        try {
            nonce_bytes = fromHexString(nonce.value);
            nonce.classList.remove("error");
        } catch (e) {
            keystream_output.value = "Nonce must be valid hex!";
            c1_output.value = "Nonce must be valid hex!";
            c2_output.value = "Nonce must be valid hex!";
            c1_xor_p1_output.value = "Nonce must be valid hex!";
            c2_xor_c1_xor_p1_output.value = "Nonce must be valid hex!";
            nonce.classList.add("error");
            return;
        }

        let key_bytes;
        try {
            key_bytes = fromHexString(key_input.value);
            key_input.classList.remove("error");
        } catch (e) {
            c1_output.value = "Key must be 32 hex digits!";
            c2_output.value = "Key must be 32 hex digits!";
            c1_xor_p1_output.value = "Key must be 32 hex digits!";
            c2_xor_c1_xor_p1_output.value = "Key must be 32 hex digits!";
            keystream_output.value = "Key must be 32 hex digits!";
            key_input.classList.add("error");
            return;
        }

        async function encrypt(plaintext_elem, ciphertext_elem) {

            let plaintext_bytes;
            try {
                plaintext_bytes = fromHexString(plaintext_elem.value);
            }
            catch (e) {
                ciphertext_elem.value = "Plaintext must be valid hex!";
                return;
            }

            let { ciphertext } = await AESGCM.encrypt(key_bytes, nonce_bytes, new Uint8Array(), plaintext_bytes);
            ciphertext_elem.value = toHexString(ciphertext);
        }

        await encrypt(p1_input, c1_output);
        await encrypt(p2_input, c2_output);


        let null_bytes = new Uint8Array(Math.max(p1_input.value.length / 2, p2_input.value.length / 2) + 2);
        let keystream = await AESGCM.encrypt(key_bytes, nonce_bytes, null_bytes, null_bytes);
        keystream_output.value = toHexString(keystream.ciphertext) + "...";
        c1_xor_p1_output.value = toHexString(keystream.ciphertext).substring(0, p1_input.value.length);
        c2_xor_c1_xor_p1_output.value = p2_input.value.substring(0, c1_output.value.length);
    }

    document.body.addEventListener("sync-aes-key", update);
    document.body.addEventListener("sync-nonce", update);
    p1_input.addEventListener("input", update);
    p2_input.addEventListener("input", update);
    update();
}

export function gcm_y0_calculation_widget(container) {
    let aes_key = document.createElement("input");
    aes_key.classList.add("sync-aes-key");
    let nonce = document.createElement("input");
    nonce.classList.add("sync-nonce");

    let y0_output = document.createElement("input");
    y0_output.disabled = true;
    aes_key.classList.add("code");
    nonce.classList.add("code");
    y0_output.classList.add("code");

    let grid = document.createElement("div");
    grid.classList.add("input-grid");
    container.appendChild(grid);

    add_label("key", aes_key, grid);
    add_label("nonce", nonce, grid);

    let p1 = document.createElement("p");
    p1.innerHTML = "The nonce is exactly 12 bytes long, so we can use it as the <code>Y<sub>0</sub></code> value directly:";
    p1.setAttribute("style", "grid-column: 1 / span 2");
    grid.appendChild(p1);

    add_label("y0", y0_output, grid);

    async function update() {
        let nonce_bytes;
        try {
            nonce_bytes = fromHexString(nonce.value);
            nonce.classList.remove("error");
        } catch (e) {
            y0_output.value = "Nonce must be valid hex!";
            nonce.classList.add("error");
            return;
        }

        let key_bytes;
        try {
            key_bytes = fromHexString(aes_key.value);
            aes_key.classList.remove("error");
        } catch (e) {
            y0_output.value = "Key must be 32 hex digits!";
            aes_key.classList.add("error");
            return;
        }

        if (nonce_bytes.length != 12) {
            p1.innerHTML = "The nonce is not 12 bytes long, so we cannot use it as the <code>Y<sub>0</sub></code> value directly. Instead we have to pass it through the <code>GHASH</code> function and use the result as the 16-byte <code>Y<sub>0</sub></code> block:"
        } else {
            p1.innerHTML = "The nonce is exactly 12 bytes long, so we can use it as the <code>Y<sub>0</sub></code> value directly:";
        }
        let cryptor = await AESGCM.new(key_bytes, nonce_bytes, new Uint8Array());
        y0_output.value = toHexString(cryptor.y0);
    }

    document.body.addEventListener("sync-aes-key", update);
    document.body.addEventListener("sync-nonce", update);
}

export function gf2_128_addition_widget(container) {
    let a_input_hex = document.createElement("input");
    let b_input_hex = document.createElement("input");
    let a_input_str = document.createElement("input");
    let b_input_str = document.createElement("input");
    let result_hex = document.createElement("input");
    let result_str = document.createElement("input");

    a_input_hex.classList.add("code");
    b_input_hex.classList.add("code");
    a_input_str.classList.add("code");
    b_input_str.classList.add("code");

    result_hex.disabled = true;
    result_str.disabled = true;
    result_hex.classList.add("code");
    result_str.classList.add("code");

    let grid = document.createElement("div");
    grid.classList.add("input-grid");
    container.appendChild(grid);

    add_label("a (polynomial)", a_input_str, grid);
    add_label("a (block)", a_input_hex, grid);
    add_label("b (polynomial)", b_input_str, grid);
    add_label("b (block)", b_input_hex, grid);
    add_label("a + b (polynomial)", result_str, grid);
    add_label("a + b (block)", result_hex, grid);

    a_input_hex.value = "60000000000000000000000000000000"
    b_input_hex.value = "a8000000000000000000000000000000"
    a_input_str.value = "x^2 + x"
    b_input_str.value = "x^4 + x^2 + 1"

    let b_str_modified = false;
    let a_str_modified = false;

    async function update() {
        let a;
        try {
            if (a_input_hex.value.length != 32) {
                result_hex.value = "A must be 16 bytes (32 hex digits)!";
                a_input_hex.classList.add("error");
                return;
            }
            a = fromHexString(a_input_hex.value);
            a_input_hex.classList.remove("error");
        } catch (e) {
            result_hex.value = "A must be valid hex!";
            a_input_hex.classList.add("error");
            return;
        }
        let b;
        try {
            if (b_input_hex.value.length != 32) {
                result_hex.value = "B must be 16 bytes (32 hex digits)!";
                b_input_hex.classList.add("error");
                return;
            }
            b = fromHexString(b_input_hex.value);
            b_input_hex.classList.remove("error");
        } catch (e) {
            result_hex.value = "B must be valid hex!";
            b_input_hex.classList.add("error");
            return;
        }
        let result = F128Element.from_block(a).add(F128Element.from_block(b));
        result_hex.value = toHexString(result.to_block());
        result_str.value = result.toString();
        if (!b_str_modified) {
            b_input_str.value = F128Element.from_block(b).toString();
        }
        if (!a_str_modified) {
            a_input_str.value = F128Element.from_block(a).toString();
        }
    }

    update();
    a_input_hex.addEventListener("input", () => {
        a_str_modified = false;
        update();
    });
    b_input_hex.addEventListener("input", () => {
        b_str_modified = false;
        update();
    });
    a_input_str.addEventListener("input", (e) => {
        a_str_modified = true;
        try {
            a_input_hex.value = toHexString(F128Element.from_string(a_input_str.value).to_block());
            a_input_str.classList.remove("error");
        } catch (e) {
            a_input_str.classList.add("error");
            return;
        }
        update();
    });
    b_input_str.addEventListener("input", (e) => {
        b_str_modified = true;
        try {
            b_input_hex.value = toHexString(F128Element.from_string(b_input_str.value).to_block());
            b_input_str.classList.remove("error");
        } catch (e) {
            b_input_str.classList.add("error");
            return;
        }
        update();
    });
}

export function gf2_128_multiplication_widget(container) {
    const a_input = document.createElement("input");
    const b_input = document.createElement("input");
    const unreduced_result = document.createElement("input");
    const result = document.createElement("input");

    a_input.value = "x^5 + 1";
    b_input.value = "x^123";
    a_input.classList.add("code");
    b_input.classList.add("code");
    unreduced_result.disabled = true;
    result.disabled = true;
    unreduced_result.classList.add("code");
    result.classList.add("code");

    const grid = document.createElement("div");
    grid.classList.add("input-grid");
    container.appendChild(grid);

    add_label("a", a_input, grid);
    add_label("b", b_input, grid);
    add_label("a ⋅ b", unreduced_result, grid);

    let p1 = document.createElement("p");
    p1.innerHTML = "The result of just multiplying the two polynomials is too large, so we have to reduce it modulo the GCM polynomial <code>x<sup>128</sup> + x<sup>7</sup> + x<sup>2</sup> + x + 1</code> to get the final result:";
    p1.setAttribute("style", "grid-column: 1 / span 2");
    grid.appendChild(p1);

    const { label: reduced_label } = add_label("a ⋅ b (reduced)", result, grid);

    function update() {
        let a;
        try {
            a = F128Element.from_string(a_input.value);
            a_input.classList.remove("error");
        } catch (e) {
            unreduced_result.value = "Invalid polynomial!";
            result.value = "Invalid polynomial!";
            a_input.classList.add("error");
            return;
        }
        let b;
        try {
            b = F128Element.from_string(b_input.value);
            b_input.classList.remove("error");
        } catch (e) {
            unreduced_result.value = "Invalid polynomial!";
            result.value = "Invalid polynomial!";
            b_input.classList.add("error");
            return;
        }
        let unreduced = a.mul_unreduced(b);
        unreduced_result.value = unreduced.toString();

        if (unreduced.degree() < 128) {
            p1.style.display = "none";
            reduced_label.style.display = "none";
            result.style.display = "none";
        } else {
            p1.style.display = "block";
            reduced_label.style.display = "block";
            result.style.display = "block";
        }

        result.value = unreduced.reduce().toString();
    }

    update();
    a_input.addEventListener("input", update);
    b_input.addEventListener("input", update);
}

export function ghash_widget(container) {
    let key = document.createElement("input");
    key.classList.add("sync-aes-key");
    let nonce = document.createElement("input");
    nonce.classList.add("sync-nonce");
    let ciphertext_input = document.createElement("input");
    let associated_data_input = document.createElement("input");

    key.classList.add("code");
    nonce.classList.add("code");
    ciphertext_input.classList.add("code");
    associated_data_input.classList.add("code");

    let grid = document.createElement("div");
    grid.classList.add("input-grid");
    container.appendChild(grid);

    add_label("key", key, grid);
    add_label("nonce", nonce, grid);
    add_label("associated data", associated_data_input, grid);
    add_label("ciphertext", ciphertext_input, grid);

    ciphertext_input.value = "cafeaffe";
    associated_data_input.value = "deadbeef";

    let dynamic_content = document.createElement("div");
    dynamic_content.classList.add("input-grid");
    container.appendChild(dynamic_content);

    function add_text(text, out) {
        let p = document.createElement("p");
        p.innerHTML = text;
        p.setAttribute("style", "grid-column: 1 / span 2");
        out.appendChild(p);
    }

    function add_block(block, blocks_out, out) {
        if (block.length < 16) {
            const newblock = new Uint8Array(16);
            newblock.set(block);
            block = newblock;
        }
        const block_hex = toHexString(block);
        const block_label = "<code> U<sub>" + blocks_out.length + "</sub></code>";
        const block_elem = document.createElement("input");
        block_elem.classList.add("code");
        block_elem.value = block_hex;
        block_elem.disabled = true;
        add_label(block_label, block_elem, out);
        blocks_out.push(block);
    }

    function add_blocks(data, blocks_out, out) {
        for (let i = 0; i < data.length; i += 16) {
            let block = data.slice(i, i + 16);
            add_block(block, blocks_out, out);
        }
    }

    function add_output(label_text, bytes, out) {
        let output = document.createElement("input");
        output.classList.add("code");
        output.value = toHexString(bytes);
        output.disabled = true;
        add_label(label_text, output, out);
    }

    async function update() {
        let key_bytes;
        try {
            if (key.value.length != 32) {
                throw new Error("Key must be 32 hex digits!");
            }
            key_bytes = fromHexString(key.value);
            key.classList.remove("error");
        } catch (e) {
            key.classList.add("error");
            return;
        }

        let nonce_bytes;
        try {
            nonce_bytes = fromHexString(nonce.value);
            nonce.classList.remove("error");
        } catch (e) {
            nonce.classList.add("error");
            return;
        }

        let associated_data_bytes;
        try {
            associated_data_bytes = fromHexString(associated_data_input.value);
            associated_data_input.classList.remove("error");
        } catch (e) {
            associated_data_input.classList.add("error");
            return;
        }

        let ciphertext_bytes;
        try {
            ciphertext_bytes = fromHexString(ciphertext_input.value);
            ciphertext_input.classList.remove("error");
        } catch (e) {
            ciphertext_input.classList.add("error");
            return;
        }

        let new_dynamic_content = document.createElement("div");
        new_dynamic_content.classList.add("input-grid");

        let cryptor = await AESGCM.new(key_bytes, nonce_bytes, associated_data_bytes);

        let first_explainer = "First we prepare the blocks for the <code>GHASH</code> function. ";
        let blocks = [];
        // Four cases:

        // 1. No associated data, no ciphertext
        if (associated_data_bytes.length == 0 && ciphertext_bytes.length == 0) {
            first_explainer += "Since there is no associated data and no ciphertext, we only need to prepare the 16-byte length block <code>U<sub>0</sub></code> filled with zeroes:";
            add_text(first_explainer, new_dynamic_content);
            const block = new Uint8Array(16);
            blocks.push(block);
            const block_hex = toHexString(block);
            const block_label = "<code> U<sub>0</sub></code>";
            const block_elem = document.createElement("input");
            block_elem.classList.add("code");
            block_elem.value = block_hex;
            block_elem.disabled = true;
            add_label(block_label, block_elem, new_dynamic_content);
        }
        // 2. No associated data, ciphertext
        else if (associated_data_bytes.length == 0) {
            first_explainer += "Since there is no associated data, we immediately prepare the blocks for the ciphertext, padding the last block with zeroes if necessary:";
            add_text(first_explainer, new_dynamic_content);
            add_blocks(ciphertext_bytes, blocks, new_dynamic_content);
            add_text("The length of the associated data is 0, so the length block only contains the length of the ciphertext, which is " + ciphertext_bytes.length + " bytes, so " + (ciphertext_bytes.length * 8) + " bits:", new_dynamic_content);
            let l = new Uint8Array(16);
            const ct_length = BigInt(ciphertext_bytes.length) * BigInt(8);
            for (let i = 0; i < 8; i++) {
                l[15 - i] = Number((ct_length >> BigInt(i * 8)) & BigInt(0xff));
            }
            add_block(l, blocks, new_dynamic_content);
        }
        // 3. If we have associated data, we always have to prepare the blocks for the associated data
        else {
            first_explainer += "We start with the blocks for the associated data:";
            add_text(first_explainer, new_dynamic_content);
            add_blocks(associated_data_bytes, blocks, new_dynamic_content);
            // If we have ciphertext, we also have to prepare the blocks for the ciphertext
            if (ciphertext_bytes.length > 0) {
                add_text("Then we prepare the blocks for the ciphertext, padding the last block with zeroes if necessary:", new_dynamic_content);
                add_blocks(ciphertext_bytes, blocks, new_dynamic_content);
            }
            const prefix = ciphertext_bytes.length > 0 ? "Finally " : "Then ";
            add_text(prefix + "we prepare the length block. The length block contains the length of the associated data (" + (associated_data_bytes.length * 8) + " bits) and the length of the ciphertext (" + (ciphertext_bytes.length * 8) + " bits), as two concatenated 64-bit values:", new_dynamic_content);

            let l = new Uint8Array(16);
            const ad_length = BigInt(associated_data_bytes.length) * BigInt(8);
            const ct_length = BigInt(ciphertext_bytes.length) * BigInt(8);
            for (let i = 0; i < 8; i++) {
                l[15 - i] = Number((ct_length >> BigInt(i * 8)) & BigInt(0xff));
                l[7 - i] = Number((ad_length >> BigInt(i * 8)) & BigInt(0xff));
            }
            add_block(l, blocks, new_dynamic_content);
        }

        add_text("To proceed, we need to calculate the <code>H</code> key by encrypting the 16-byte zero block with the AES key:", new_dynamic_content);

        add_output("H", cryptor.h, new_dynamic_content);

        add_text("Now we can calculate the <code>GHASH</code> value by processing the blocks one by one. We start off by setting <code>Q</code> to zero:", new_dynamic_content);

        let q = new Uint8Array(16);
        add_output("Q", q, new_dynamic_content);

        if (blocks.length == 1) {
            // Special case: Only one block
            add_text("Since there is only one block, and it is zero, the result of the multiplication is zero as well, so the final <code>GHASH</code> value is zero:", new_dynamic_content);

            add_output("GHASH", q, new_dynamic_content);
        } else {
           let h = F128Element.from_block(cryptor.h);
           for (let i = 0; i < blocks.length; i++) {
                let block = blocks[i];
                if (i == 0) {
                    add_text("First, we add the first block <code>U<sub>0</sub></code> to <code>Q</code> and multiply the result by <code>H</code>:", new_dynamic_content);
                    q = F128Element.from_block(block).add(F128Element.from_block(q)).to_block();
                    add_output("Q ← Q ⊕ <code>U<sub>0</sub>", q, new_dynamic_content);
                    q = F128Element.from_block(q).mul(h).to_block();
                    add_output("Q ← Q ⨂ H", q, new_dynamic_content);
                    continue;
                } else if (i == 1) {
                    add_text("We repeat this for all other blocks, starting with the second block <code>U<sub>1</sub></code>:", new_dynamic_content);
                }
                q = F128Element.from_block(block).add(F128Element.from_block(q)).mul(h).to_block();
                add_output("Q ← (Q ⊕ <code>U<sub>" + i + "</sub>) ⨂ H", q, new_dynamic_content);
            }

            add_text("Finally, we have processed all blocks so final <code>GHASH</code> value is:", new_dynamic_content);
            add_output("GHASH", q, new_dynamic_content);
        }

        add_text("Lastly, we have to add <code>E<sub>k</sub>(Y<sub>0</sub>)</code> to the <code>GHASH</code> value to get the final authentication tag:", new_dynamic_content);

        let y0 = F128Element.from_block(cryptor.y_block(0));
        let ek_y0 = F128Element.from_block(await cryptor.raw_aes(y0.to_block()));
        let tag = F128Element.from_block(q).add(ek_y0).to_block();

        add_output("Y<sub>0</sub>", y0.to_block(), new_dynamic_content);
        add_output("E<sub>k</sub>(Y<sub>0</sub>)", ek_y0.to_block(), new_dynamic_content);
        add_output("T = GHASH ⊕ E<sub>k</sub>(Y<sub>0</sub>)", tag, new_dynamic_content);

        dynamic_content.replaceWith(new_dynamic_content);
        dynamic_content = new_dynamic_content;
    }

    document.body.addEventListener("sync-aes-key", update);
    document.body.addEventListener("sync-nonce", update);
    associated_data_input.addEventListener("input", update);
    ciphertext_input.addEventListener("input", update);
}

export function aes_gcm_widget(container, pt_value, sync_suffix, hide_key_and_nonce) {
    if (!sync_suffix) {
        sync_suffix = "";
    }
    let key = document.createElement("input");
    key.classList.add("sync-aes-key");
    let nonce = document.createElement("input");
    nonce.classList.add("sync-nonce");
    let plaintext_input = document.createElement("input");
    plaintext_input.classList.add("sync-plaintext" + sync_suffix);
    if (pt_value) {
        plaintext_input.value = pt_value;
    }

    let ciphertext_input = document.createElement("input");
    ciphertext_input.classList.add("sync-ciphertext" + sync_suffix);
    let tag_input = document.createElement("input");
    tag_input.classList.add("sync-tag" + sync_suffix);

    key.classList.add("code");
    nonce.classList.add("code");
    plaintext_input.classList.add("code");
    ciphertext_input.classList.add("code");

    let grid = document.createElement("div");
    grid.classList.add("input-grid");
    container.appendChild(grid);
    

    let { label: key_label } = add_label("key", key, grid);
    let { label: nonce_label } = add_label("nonce", nonce, grid);
    if (hide_key_and_nonce === true) {
        key.style.display = "none";
        nonce.style.display = "none";
        key_label.style.display = "none";
        nonce_label.style.display = "none";
    }
    let text_suffix = sync_suffix == "" ? "" : ` (${sync_suffix})`;
    add_label("plaintext" + text_suffix, plaintext_input, grid);
    add_label("ciphertext" + text_suffix, ciphertext_input, grid);
    add_label("tag" + text_suffix, tag_input, grid);

    async function updateCiphertext() {
        tag_input.classList.remove("error");
        ciphertext_input.classList.remove("error");
        let key_bytes;
        try {
            if (key.value.length != 32) {
                throw new Error("Key must be 32 hex digits!");
            }
            key_bytes = fromHexString(key.value);
            key.classList.remove("error");
        } catch (e) {
            key.classList.add("error");
            return;
        }

        let nonce_bytes;
        try {
            nonce_bytes = fromHexString(nonce.value);
            nonce.classList.remove("error");
        } catch (e) {
            nonce.classList.add("error");
            return;
        }

        let plaintext_bytes;
        try {
            plaintext_bytes = fromHexString(plaintext_input.value);
            plaintext_input.classList.remove("error");
        } catch (e) {
            plaintext_input.classList.add("error");
            return;
        }

        let { ciphertext, auth_tag } = await AESGCM.encrypt(key_bytes, nonce_bytes, new Uint8Array(), plaintext_bytes);

        ciphertext_input.value = toHexString(ciphertext);
        ciphertext_input.dispatchEvent(new Event("input"));
        tag_input.value = toHexString(auth_tag);
        tag_input.dispatchEvent(new Event("input"));
    }

    async function updatePlaintext() {
        let key_bytes;
        try {
            if (key.value.length != 32) {
                throw new Error("Key must be 32 hex digits!");
            }
            key_bytes = fromHexString(key.value);
            key.classList.remove("error");
        } catch (e) {
            key.classList.add("error");
            return;
        }

        let nonce_bytes;
        try {
            nonce_bytes = fromHexString(nonce.value);
            nonce.classList.remove("error");
        } catch (e) {
            nonce.classList.add("error");
            return;
        }

        let ciphertext_bytes;
        try {
            ciphertext_bytes = fromHexString(ciphertext_input.value);
            ciphertext_input.classList.remove("error");
        } catch (e) {
            ciphertext_input.classList.add("error");
            return;
        }

        let tag_bytes;
        try {
            if (tag_input.value.length != 32) {
                throw new Error("Tag must be 16 bytes (32 hex digits)!");
            }
            tag_bytes = fromHexString(tag_input.value);
            tag_input.classList.remove("error");
        } catch (e) {
            tag_input.classList.add("error");
            return;
        }
        try {
            let plaintext = await AESGCM.decrypt(key_bytes, nonce_bytes, new Uint8Array(), ciphertext_bytes, tag_bytes);
            plaintext_input.classList.remove("error");
            plaintext_input.value = toHexString(plaintext);
        } catch (e) {
            plaintext_input.classList.add("error");
        }
    }

    document.body.addEventListener("sync-aes-key", updateCiphertext);
    document.body.addEventListener("sync-nonce", updateCiphertext);
    document.body.addEventListener("sync-plaintext" + sync_suffix, updateCiphertext);
    document.body.addEventListener("sync-ciphertext" + sync_suffix, updatePlaintext);
    document.body.addEventListener("sync-tag" + sync_suffix, updatePlaintext);
    setTimeout(updateCiphertext, 0);
}

export function construct_polynomial_widget(container) {
    let ct1_input = document.createElement("input");
    let ct2_input = document.createElement("input");
    let t1_input = document.createElement("input");
    let t2_input = document.createElement("input");
    ct1_input.classList.add("sync-ciphertext1");
    ct2_input.classList.add("sync-ciphertext2");
    t1_input.classList.add("sync-tag1");
    t2_input.classList.add("sync-tag2");

    ct1_input.style.display = "none";
    ct2_input.style.display = "none";
    t1_input.style.display = "none";
    t2_input.style.display = "none";
    container.appendChild(ct1_input);
    container.appendChild(ct2_input);
    container.appendChild(t1_input);
    container.appendChild(t2_input);
    let dynamic_content = document.createElement("div");
    container.appendChild(dynamic_content);

    function update() {
        let ct1;
        let ct2;
        let t1;
        let t2;
        try {
            ct1 = fromHexString(ct1_input.value);
            ct2 = fromHexString(ct2_input.value);
            t1 = fromHexString(t1_input.value);
            t2 = fromHexString(t2_input.value);
        } catch (e) {
            return;
        }

        dynamic_content.innerHTML = "";
    
        let blocks1 = get_blocks(ct1);
        let blocks2 = get_blocks(ct2);
        let max_length = Math.max(blocks1.length, blocks2.length);
        blocks1.reverse();
        while (blocks1.length < max_length) {
            blocks1.push(new Uint8Array(16));
        }
        blocks1.reverse();
        blocks2.reverse();
        while (blocks2.length < max_length) {
            blocks2.push(new Uint8Array(16));
        }
        blocks2.reverse();

        let p = document.createElement("p");
        p.innerHTML = "First, we split the first ciphertext into its 16-byte blocks used during the <code>GHASH</code> calculation:";
        dynamic_content.appendChild(p);
        let ul = document.createElement("ul");
        for (let i = 0; i < blocks1.length; i++) {
            let block = blocks1[i];
            let block_label = "<code> U1<sub>" + i + "</sub></code>";
            let block_elem = document.createElement("li");
            block_elem.innerHTML = block_label + ": <code>" + toHexString(block) + "</code>";
            ul.appendChild(block_elem);
        }
        dynamic_content.appendChild(ul);

        let p2 = document.createElement("p");
        p2.innerHTML = "Then we do the same for the second ciphertext:";
        dynamic_content.appendChild(p2);
        let ul2 = document.createElement("ul");
        for (let i = 0; i < blocks2.length; i++) {
            let block = blocks2[i];
            let block_label = "<code> U2<sub>" + i + "</sub></code>";
            let block_elem = document.createElement("li");
            block_elem.innerHTML = block_label + ": <code>" + toHexString(block) + "</code>";
            ul2.appendChild(block_elem);
        }
        dynamic_content.appendChild(ul2);

        let p3 = document.createElement("p");
        p3.innerHTML = "Now we can calculate the polynomial equation by XORing the blocks of the two ciphertexts together. I'll represent the coefficients of the polynomial in the GCM block representation instead of <code>GF(2)</code> polynomials because it's easier to read:";
        dynamic_content.appendChild(p3);

        let p_str = "T1 ⊕ T2<br/>= ";
        for (let i = 0; i < max_length; i++) {
            let block1 = blocks1[i] || new Uint8Array(16);
            let block2 = blocks2[i] || new Uint8Array(16);
            p_str += "((" + toHexString(block1) + " ⊕ " + toHexString(block2) + ") ⨂ H<sup>" + (max_length - i) + "</sup>) ";
            if (i < max_length - 1) {
                p_str += "<br/>⊕ ";
            }
        }
        p_str += "<br/>= ";
        let equation = "";
        for (let i = 0; i < max_length; i++) {
            let block1 = blocks1[i] || new Uint8Array(16);
            let block2 = blocks2[i] || new Uint8Array(16);
            let result = F128Element.from_block(block1).add(F128Element.from_block(block2)).to_block();
            if (toHexString(result) == "00000000000000000000000000000000") {
                continue;
            }
            let part = "(" + toHexString(result) + " ⨂ H<sup>" + (max_length - i) + "</sup>)";
            equation += part + " ⊕ ";
            p_str += part + "<br/>⊕ ";
        }

        p_str = p_str.substring(0, p_str.length - 7);
        equation = equation.substring(0, equation.length - 3);
        if (equation == "") {
            equation = "00000000000000000000000000000000";
        }

        let p4 = document.createElement("pre");
        p4.innerHTML = p_str;
        dynamic_content.appendChild(p4);

        let p5 = document.createElement("p");
        p5.innerHTML = "The last step in constructing the polynomial is to calculate <code>T1 ⊕ T2</code>, which simply means XORing the two tags together. Therefore, we have the equation:";
        dynamic_content.appendChild(p5);

        let p6 = document.createElement("pre");
        p6.innerHTML = equation + "<br/>= " + toHexString(t1) + " ⊕ " + toHexString(t2) + "<br/>= " + toHexString(t1.map((v, i) => v ^ t2[i]));
        dynamic_content.appendChild(p6);

        let p7 = document.createElement("p");

        p7.innerHTML = "By moving last term to the other side of the equation, we get the final polynomial we can use to recover the <code>GHASH</code> key <code>H</code>:";
        dynamic_content.appendChild(p7);

        let p8 = document.createElement("pre");
        p8.innerHTML =  equation + " ⊕ " + toHexString(t1.map((v, i) => v ^ t2[i])) + " = 0";
        dynamic_content.appendChild(p8);
    }

    document.body.addEventListener("sync-ciphertext1", update);
    document.body.addEventListener("sync-ciphertext2", update);
    document.body.addEventListener("sync-tag1", update);
    document.body.addEventListener("sync-tag2", update);
    update();
}

export function h_candidates_widget(container) {
    let ct1_input = document.createElement("input");
    let ct2_input = document.createElement("input");
    let ct3_input = document.createElement("input");
    let t1_input = document.createElement("input");
    let t2_input = document.createElement("input");
    let t3_input = document.createElement("input");
    ct1_input.classList.add("sync-ciphertext1");
    ct2_input.classList.add("sync-ciphertext2");
    ct3_input.classList.add("sync-ciphertext3");
    t1_input.classList.add("sync-tag1");
    t2_input.classList.add("sync-tag2");
    t3_input.classList.add("sync-tag3");

    ct1_input.style.display = "none";
    ct2_input.style.display = "none";
    ct3_input.style.display = "none";
    t1_input.style.display = "none";
    t2_input.style.display = "none";
    t3_input.style.display = "none";
    container.appendChild(ct1_input);
    container.appendChild(ct2_input);
    container.appendChild(ct3_input);
    container.appendChild(t1_input);
    container.appendChild(t2_input);
    container.appendChild(t3_input);

    let dynamic_content = document.createElement("div");
    container.appendChild(dynamic_content);

    function update() {
        let ct1;
        let ct2;
        let ct3;
        let t1;
        let t2;
        let t3;
        try {
            ct1 = fromHexString(ct1_input.value);
            ct2 = fromHexString(ct2_input.value);
            ct3 = fromHexString(ct3_input.value);
            t1 = fromHexString(t1_input.value);
            t2 = fromHexString(t2_input.value);
            t3 = fromHexString(t3_input.value);
        } catch (e) {
            return;
        }
        let blocks1 = get_blocks(ct1);
        let blocks2 = get_blocks(ct2);
        let max_length = Math.max(blocks1.length, blocks2.length);
        blocks1.reverse();
        while (blocks1.length < max_length) {
            blocks1.push(new Uint8Array(16));
        }
        blocks1.reverse();
        blocks2.reverse();
        while (blocks2.length < max_length) {
            blocks2.push(new Uint8Array(16));
        }
        blocks2.reverse();

        let coeffs = [];
        for (let i = 0; i < max_length; i++) {
            let block1 = blocks1[i] || new Uint8Array(16);
            let block2 = blocks2[i] || new Uint8Array(16);
            let result = F128Element.from_block(block1).add(F128Element.from_block(block2)).to_block();
            coeffs.push(result);
        }
        coeffs.push(t1.map((v, i) => v ^ t2[i]));
        coeffs.reverse();

        let coeffs_encoded = coeffs.map(toHexString);

        while (coeffs_encoded.length > 0 && coeffs_encoded[0] == "00000000000000000000000000000000") {
            coeffs_encoded.splice(0, 1);
        }

        if (coeffs_encoded.length == 0) {
            dynamic_content.innerHTML = "";
            let p = document.createElement("p");
            p.innerHTML = "In this case, because the two ciphertexts are identical, we get an equation that's always true. Think about it like this: If it were possible to break AES-GCM with two identical messages, then it would be possible to just take the same message twice and apply the Cantor-Zassenhaus algorithm, which would paradoxically lead to a full break of AES-GCM every time you get any plaintext / ciphertext pair, even without nonce reuse. You have to enter two different plaintexts to be able to continue.";
            dynamic_content.appendChild(p);
            return;
        }

        let square_free_coeffs = square_free(coeffs_encoded);

        if (square_free_coeffs.length == 1) {
            // This is an edge-case due to update-logic.
            // The next update contains "correct" data again.
            return;
        }

        let was_square_free = square_free_coeffs.length == coeffs_encoded.length;
        dynamic_content.innerHTML = "";
        if (!was_square_free) {
            let p = document.createElement("p");
            p.innerHTML = "The equation is not square free. As a first step, we apply the square free factorization algorithm to get a polynomial that has exactly the same roots as the original polynomial, but with any duplicate zeros removed. This gives us the following polynomial equation:";
            let square_free_code = document.createElement("pre");
            square_free_code.innerHTML = hexPolyToHTML(square_free_coeffs);
            dynamic_content.appendChild(p);
            dynamic_content.appendChild(square_free_code);
	    }



        let distinct_degree_factors_raw = distinct_degree(square_free_coeffs);
        let current = [];
        let distinct_degree_factors = [];

        for(let i = 0; i < distinct_degree_factors_raw.length - 1; i++) {
            current.push(distinct_degree_factors_raw[i]);
            if (distinct_degree_factors_raw[i+2] == "") {
                distinct_degree_factors.push([current.slice(), parseInt(distinct_degree_factors_raw[i+1])]);
                i += 2;
            }
        }

        {
            let p = document.createElement("p");
            p.innerHTML = "By using the distinct degree algorithm, we obtain the following polynomial equations:";
            let ul = document.createElement("ul");
            for (let i = 0; i < distinct_degree_factors.length; i++) {
                let li = document.createElement("li");
                li.innerHTML = "<code>" + hexPolyToHTML(distinct_degree_factors[i][0]) + "</code> (factors of degree " + distinct_degree_factors[i][1] + ")";
                ul.appendChild(li);
            }
            dynamic_content.appendChild(p);
            dynamic_content.appendChild(ul);
        }

        let zeros = find_zeros(coeffs_encoded);

        {
            let p = document.createElement("p");
            p.innerHTML = "We're only interested in the equation with factors of degree 1, as all other equations won't have any roots. The equation with factors of degree 1 fulfills both requirements for the Cantor-Zassenhaus algorithm, so we can use the algorithm to obtain a list of of solutions for the equation. The Cantor-Zassenhaus algorithm gives us the following roots for the polynomial:";
    
    
            dynamic_content.appendChild(p);
            let ul = document.createElement("ul");
            for (let zero of zeros) {
                let li = document.createElement("li");
                li.innerHTML = "<code>" + zero + "</code>";
                ul.appendChild(li);
            }
            dynamic_content.appendChild(ul);
        }

        if (zeros.legth == 1)
        {
            let p = document.createElement("p");
            p.innerHTML = "Because there's only one root, this has to be the actual <code>H</code> key used during the AES-GCM authentication.";
            dynamic_content.appendChild(p);
        }
        else
        {
            let p = document.createElement("p");
            p.innerHTML = "In this case, there are multiple values that fulfill the equation, so we need to figure out which one is the real <code>H</code> value. We can use the third message for this. We simply try to generate an authentication tag using the candidate <code>H</code> value and see if it matches up with the real authentication tag. If it does, we have found the <code>H</code> key used during the AES-GCM authentication.";
            dynamic_content.appendChild(p);
            
            let split = document.createElement("p");
            split.innerHTML = "As for ciphertext one and two, we'll have to split the ciphertext of the third message into the blocks used during the <code>GHASH</code> computation (including the length block at the end!):";
            dynamic_content.appendChild(split);

            let blocks3 = get_blocks(ct3);
            let ul = document.createElement("ul");
            for (let i = 0; i < blocks3.length; i++) {
                let block = blocks3[i];
                let block_label = "<code> U3<sub>" + i + "</sub></code>";
                let block_elem = document.createElement("li");
                block_elem.innerHTML = block_label + ": <code>" + toHexString(block) + "</code>";
                ul.appendChild(block_elem);
            }
            dynamic_content.appendChild(ul);

            let explain = document.createElement("p");
            explain.innerHTML = "Now, for each candidate value, we need to do two things: First, we need to figure out the value of <code>E<sub>k</sub>(Y<sub>0</sub>)</code> given the candidate key. Remember that the encrypted <code>Y<sub>0</sub></code> block cancelled out when we constructed the equation. To \"recover\" it, we calculate <code>GHASH</code> for the ciphertext of the first messsage and XOR the result with the actual tag of the first message. By definition, this is the <code>E<sub>k</sub>(Y<sub>0</sub>)</code> block. Second, we caculate <code>GHASH</code> for the third message and use the <code>E<sub>k</sub>(Y<sub>0</sub>)</code> value from the first step. If the result matches up with the actual value of the third tag, we have found <code>H</code>!";
            dynamic_content.appendChild(explain);

            let xor = function (ghash, t) {
                let ey0 = new Uint8Array(16);
                for (let i = 0; i < 16; i++) {
                    ey0[i] = ghash[i] ^ t[i];
                }
                return ey0;
            }

            for(let i = 0; i < zeros.length; i++) {
                let h_candidate = fromHexString(zeros[i]);
                let ghash = GHASH.ghash(ct1, new Uint8Array(), h_candidate);
                let ghash_hex = toHexString(ghash);
                let ey0 = xor(ghash, t1);
                let candidate_p = document.createElement("p");
                candidate_p.innerHTML = "For the <code>H</code> value <code>" + zeros[i] + "</code>, <code>GHASH</code> of the first message gives us <code>" + ghash_hex + "</code>. Assuming this was the real <code>GHASH</code> output for the first message, the value of the encrypted <code>Y<sub>0</sub></code> block must have been <code>" + toHexString(ey0) + "</code>. ";
                dynamic_content.appendChild(candidate_p);

                let ghash_ct3 = GHASH.ghash(ct3, new Uint8Array(), h_candidate);
                let candidate_t3 = xor(ghash_ct3, ey0);
                candidate_p.innerHTML += "Using the H value to calculate <code>GHASH</code> of the third message and XORing with <code>E<sub>k</sub>(Y<sub>0</sub>)</code> yields <code>" + toHexString(candidate_t3) + "</code>. ";

                if (toHexString(candidate_t3) == toHexString(t3)) {
                    candidate_p.innerHTML += "This matches up with the real tag of the third message. This means that this value for <code>H</code> is the real <code>H</code> value used during the AES-GCM authentication! We can use <code>H = " + zeros[i] + "</code> and <code>E<sub>k</sub>(Y<sub>0</sub>) = " + toHexString(ey0) + "</code> to perfectly replicate the authentication tag, without knowing the AES key!";
                    break;
                } else {
                    candidate_p.innerHTML += "This does not match up with the real tag of the third message. Although this value for <code>H</code> is a solution to the equation, it isn't the real value used in <code>GHASH</code>.";
                }
            }
        }
    }

    init().then(() => {
        document.body.addEventListener("sync-ciphertext1", update);
        document.body.addEventListener("sync-ciphertext2", update);
        document.body.addEventListener("sync-tag1", update);
        document.body.addEventListener("sync-tag2", update);
        update();
    });
}
