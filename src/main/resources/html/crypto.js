
function stringToBytes(str) {
    return new TextEncoder().encode(str);
}

function bytesToString(ary) {
    return new TextDecoder().decode(ary);
}

function bytesToBase64String(ary) {
    let str = "";
    for (let i = 0; i < ary.length; i++) {
        str += String.fromCharCode(ary[i]);
    }
    return btoa(str);
}

function base64StringToBytes(base64Str) {
    let str = atob(base64Str);
    let ary = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
        ary[i] = str.charCodeAt(i);
    }
    return ary;
}

/**
 * See https://github.com/mdn/dom-examples/blob/main/web-crypto/derive-key/pbkdf2.js
 * 
 * salt is 16 bytes for PBKDF2
 */
async function createKey(salt, password) {
    let keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        stringToBytes(password),
        "PBKDF2",
        false,
        ["deriveBits", "deriveKey"],
    );
    let key = await window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt,
            iterations: 100000,
            hash: "SHA-256",
        },
        keyMaterial,
        { 
            name: "AES-GCM", 
            length: 256 
        },
        true,
        ["encrypt", "decrypt"],
    );
    return key;
}

/**
 * See https://github.com/mdn/dom-examples/blob/main/web-crypto/encrypt-decrypt/aes-gcm.js
 * 
 * iv is 12 bytes for AES-GCM
 */
async function encryptMessage(key, iv, plainText) {
    let plainTextBytes = stringToBytes(plainText);
    let cipherTextBytes = new Uint8Array(await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        key,
        plainTextBytes
    ));
    let cipherText = bytesToBase64String(cipherTextBytes);
    return cipherText;
}

/**
 * See https://github.com/mdn/dom-examples/blob/main/web-crypto/encrypt-decrypt/aes-gcm.js
 * 
 * iv is 12 bytes for AES-GCM
 */
async function decryptMessage(key, iv, cipherText) {
    let cipherTextBytes = base64StringToBytes(cipherText);
    let plainTextBytes = new Uint8Array(await window.crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        key,
        cipherTextBytes
    ));
    let plainText = bytesToString(plainTextBytes);
    return plainText;
}

document.querySelector("#show-more").addEventListener("click", function() { 
    document.querySelector("#more").style.display = "block";
});

document.querySelector("#encrypt").addEventListener("click", async function() {
    try {
        let password = document.querySelector("#password").value;
        let salt = window.crypto.getRandomValues(new Uint8Array(16));
        let iv = window.crypto.getRandomValues(new Uint8Array(12));
        let key = await createKey(salt, password);
        let plainText = document.querySelector("#plaintext-in").value;
        let cipherText = await encryptMessage(key, iv, plainText);
        let cipherTextParts = bytesToBase64String(salt) + ":" + bytesToBase64String(iv) + ":" + cipherText;
        document.querySelector("#password").value = "";
        document.querySelector("#cipherText").innerHTML = cipherTextParts;
        console.log("cipherText:", cipherTextParts);
    } catch(e) {
        console.log("exception", e);
        document.querySelector("#cipherText").innerHTML = "ERROR";
    }
});

document.querySelector("#decrypt").addEventListener("click", async function() {
    try {
        let password = document.querySelector("#password").value;
        let cipherTextParts = document.querySelector("#cipherText").innerHTML.split(":");
        let salt = base64StringToBytes(cipherTextParts[0]);
        let iv = base64StringToBytes(cipherTextParts[1]);
        let cipherText = cipherTextParts[2];
        let key = await createKey(salt, password);
        let plainText = await decryptMessage(key, iv, cipherText);
        document.querySelector("#password").value = "";
        document.querySelector("#plaintext-in").value = plainText;
        document.querySelector("#plaintext").innerHTML = plainText;
    } catch(e) {
        console.log("exception", e);
        document.querySelector("#plaintext").innerHTML = "ERROR";
    }
});
