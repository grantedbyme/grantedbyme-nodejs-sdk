/*
 * =BEGIN MIT LICENSE
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2016 GrantedByMe
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * =END MIT LICENSE
 */
module.exports = (function () {
    "use strict";

    /**
     * Creates a new GBMCrypto instance.
     * @param crypto {crypto} The crypto object
     * @param private_key {String|Object} The PEM encoded service private key
     * @param server_key {String|Object} The PEM encoded server public key
     * @constructor
     */
    function GBMCrypto(crypto, private_key, server_key) {
        this.crypto = crypto;
        this.private_key = private_key;
        this.server_key = server_key;
    }

    /**
     * Encrypts a buffer using compound AES and/or RSA algorithms depending on the input size.
     * @param {Buffer} data The input data.
     * @returns {{payload: String, signature: String, public_hash: String, alg: String}}
     */
    GBMCrypto.prototype.encrypt = function (data) {
        // serialize input buffer data to JSON string
        const plain_text = JSON.stringify(data);
        // create new buffer from JSON string
        const buffer = new Buffer(plain_text);
        // use RSA encryption and signature if message is short enough,
        // otherwise use compound AES + RSA encryption and signing
        if (buffer.length < 215) {
            // encrypt input buffer using RSA encryption
            const rsa_result = this.crypto.publicEncrypt(this.server_key, buffer);
            // generate input buffer signature using RSA-SHA512
            const sign = this.crypto.createSign('RSA-SHA512');
            sign.update(buffer);
            const signature_rsa = sign.sign(this.private_key, 'base64');
            // return result object
            return {
                payload: rsa_result.toString('base64'),
                signature: signature_rsa,
                public_hash: this.sha512(this.server_key),
                alg: 'RS512'
            };
        } else {
            // generate AES key and initialization vector
            const key = this.random_bytes(32);
            const iv = this.random_bytes(16);
            // encrypt input buffer using AES-256-CBC algorithm
            const cipher = this.crypto.createCipheriv('AES-256-CBC', key, iv);
            var aes_result = cipher.update(buffer, 'utf8', 'base64');
            aes_result += cipher.final('base64');
            // generate HMAC-SHA256 signature of input buffer
            const hmac = this.crypto.createHmac('sha256', key);
            hmac.update(buffer);
            const signature_aes = hmac.digest('base64');
            // wrap AES encryption data using RSA encryption
            const buffer_aes = new Buffer(JSON.stringify({
                cipher_key: key.toString('base64'),
                cipher_iv: iv.toString('base64'),
                signature: signature_aes,
                timestamp: new Date().getTime()
            }));
            const rsa_result = this.crypto.publicEncrypt(this.server_key, buffer_aes);
            // generate wrapped data signature
            const sign = this.crypto.createSign('RSA-SHA512');
            sign.update(buffer_aes);
            const rsa_signature = sign.sign(this.private_key, 'base64');
            // return result object
            return {
                payload: rsa_result.toString('base64'),
                signature: rsa_signature,
                message: aes_result.toString('base64'),
                public_hash: this.sha512(this.server_key),
                alg: 'RS512'
            };
        }
    };

    /**
     * Decrypts a buffer using compound AES and/or RSA algorithms depending on the input size.
     * @param {Buffer} data The input data.
     * @returns {Object|null}
     */
    GBMCrypto.prototype.decrypt = function (data) {
        // decrypts payload using RSA private key
        const cipher_data = this.crypto.privateDecrypt(this.private_key, new Buffer(data.payload, 'base64'));
        // verify signature of decrypted data
        const verify = this.crypto.createVerify('RSA-SHA512');
        verify.update(cipher_data);
        const is_valid = verify.verify(this.server_key, data.signature, 'base64');
        if (is_valid) {
            // serialize plain text to JSON object
            const cipher_json = JSON.parse(cipher_data);
            // check for compound AES+RSA encryption
            if (data.message) {
                // decrypt aes
                const decipher = this.crypto.createDecipheriv('AES-256-CBC', new Buffer(cipher_json.cipher_key, 'base64'), new Buffer(cipher_json.cipher_iv, 'base64'));
                var decrypted = decipher.update(data.message, 'base64', 'utf8');
                decrypted += decipher.final('utf8');
                // verify aes
                const hmac = this.crypto.createHmac('sha256', new Buffer(cipher_json.cipher_key, 'base64'));
                hmac.update(new Buffer(decrypted));
                if (hmac.digest('base64') === cipher_json.signature) {
                    return JSON.parse(decrypted);
                } else {
                    console.log('Invalid AES signature!');
                    return null;
                }
            }
            return cipher_json;
        } else {
            console.log('Invalid RSA signature!');
        }

        return null;
    };

    ////////////////////////////////////////
    // Helpers
    ////////////////////////////////////////

    /**
     * Generates a hash digest using SHA-512 algorithm.
     * Additionally normalizes the line endings of the input string for Unix/Windows consistency.
     * @param {String} data The input to generate digest of.
     * @returns {String} The generated digest hex string.
     */
    GBMCrypto.prototype.sha512 = function (data) {
        const hash = this.crypto.createHash('sha512');
        data = data.replace('\r\n', '\n');
        data = data.replace('\r', '\n');
        hash.update(data);
        return hash.digest('hex');
    };

    /**
     * Generates cryptographically strong pseudo-random data.
     * @param {Number} length The length of string to generate.
     * @returns {String} Returns the generated string.
     */
    GBMCrypto.prototype.random_string = function (length) {
        return this.random_bytes(length * 0.5).toString('hex');
    };

    /**
     * Generates cryptographically strong pseudo-random data.
     * @param {Number} length The number of bytes to generate.
     * @returns {Buffer} The generated bytes.
     */
    GBMCrypto.prototype.random_bytes = function (length) {
        return this.crypto.randomBytes(length);
    };

    return GBMCrypto;
}());
