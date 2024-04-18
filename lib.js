"use strict";

const { getRandomValues } = require('crypto');

const crypto = require('crypto');
/**
 * Converts a plaintext string into a buffer for use in SubtleCrypto functions.
 * @param {string} str - A plaintext string
 * @returns {Buffer} A buffer representation for use in SubtleCrypto functions
 */
function stringToBuffer(str) {
    return Buffer.from(str);
}

/**
 * Converts a buffer object representing string data back into a string
 * @param {BufferSource} buf - A buffer containing string data
 * @returns {string} The original string
 */
function bufferToString(buf) {
    return Buffer.from(buf).toString();
}

/**
 * Converts a buffer to a Base64 string which can be used as a key in a map and
 * can be easily serialized.
 * @param {BufferSource} buf - A buffer-like object
 * @returns {string} A Base64 string representing the bytes in the buffer
 */
function encodeBuffer(buf) {
    return Buffer.from(buf).toString('base64');
}

/**
 * Converts a Base64 string back into a buffer
 * @param {string} base64 - A Base64 string representing a buffer
 * @returns {Buffer} A Buffer object
 */
function decodeBuffer(base64) {
    return Buffer.from(base64, "base64")
}

/**
 * Generates a buffer of random bytes
 * @param {number} len - The number of random bytes
 * @returns {Uint8Array} A buffer of `len` random bytes
 */
function getRandomBytes(len) {
    return getRandomValues(new Uint8Array(len))
}

/**
 * Encrypts the given plain text using AES-256-GCM algorithm.
 * 
 * @param {string} plain_text - The plain text to be encrypted.
 * @param {string} key - The encryption key.
 * @returns {string|null} The encrypted cipher text, or null if encryption fails.
 */
function cipherIV(plain_text, key) 
{

    const iv = crypto.randomBytes(32);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    let cipher_text;
    try {
        cipher_text = cipher.update(plain_text, 'utf8', 'hex');
        cipher_text = iv.toString('hex') + cipher_text
    } catch (e) {
        cipher_text = null;
    }
    return cipher_text;
}


/**
 * Decrypts the given cipher text using the provided key and initialization vector (IV).
 *
 * @param {string} cipher_text - The cipher text to decrypt.
 * @param {string} key - The encryption key.
 * @returns {string} The decrypted text.
 */
function decipherIV(cipher_text, key) 
{
    const contents = Buffer.from(cipher_text, 'hex');
    const iv = contents.slice(0, 32);
    const textBytes = contents.slice(32);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    
    let decrypted = decipher.update(textBytes, 'hex', 'utf8');
    return decrypted;
}

module.exports = {
    stringToBuffer,
    bufferToString,
    encodeBuffer,
    decodeBuffer,
    getRandomBytes,
    cipherIV,
    decipherIV
}