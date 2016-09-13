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

    function GBMCrypto(crypto, private_key, server_key) {
        this.crypto = crypto;
        this.private_key = private_key;
        this.server_key = server_key;
    }

    // RSA

    GBMCrypto.prototype.encrypt_rsa = function (data) {
        return this.crypto.publicEncrypt(this.server_key, data);
    };

    GBMCrypto.prototype.decrypt_rsa = function (data) {
        return this.crypto.privateDecrypt(this.private_key, data);
    };

    GBMCrypto.prototype.sign_rsa = function (data) {
        const sign = this.crypto.createSign('RSA-SHA512');
        sign.update(data);
        return sign.sign(this.private_key, 'base64');
    };

    GBMCrypto.prototype.verify_rsa = function (data, signature) {
        const verify = this.crypto.createVerify('RSA-SHA512');
        verify.update(data);
        return verify.verify(this.server_key, signature, 'base64');
    };

    // AES

    GBMCrypto.prototype.encrypt_aes = function (data, key, iv) {
        const cipher = this.crypto.createCipheriv('AES-128-CBC', key, iv);
        // input: 'utf8', 'ascii', or 'latin1'
        // output: 'latin1', 'base64' or 'hex'
        var encrypted = cipher.update(data, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        return encrypted;
    };

    GBMCrypto.prototype.decrypt_aes = function (data, key, iv) {
        const decipher = this.crypto.createDecipheriv('AES-128-CBC', key, iv);
        // input: 'latin1', 'base64' or 'hex'
        // output: 'utf8', 'ascii', or 'latin1'
        var decrypted = decipher.update(data, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    };

    GBMCrypto.prototype.sign_aes = function (data, key) {
        const hmac = crypto.createHmac('sha256', key);
        hmac.update(data);
        return hmac.digest('hex');
    };

    GBMCrypto.prototype.verify_aes = function (data, key, signature) {
        const hmac = crypto.createHmac('sha256', key);
        hmac.update(data);
        return hmac.digest('hex') === signature;
    };

    // Compound

    GBMCrypto.prototype.encrypt = function (data) {
        var plain_text = JSON.stringify(data);
        var buffer = new Buffer(plain_text);
        var rsa_result = this.encrypt_rsa(buffer);
        var rsa_signature = this.sign_rsa(buffer);
        return {
            payload: rsa_result.toString('base64'),
            signature: rsa_signature.toString(),
            public_hash: this.sha512(this.server_key),
            alg: 'RS512'
        };
    };

    GBMCrypto.prototype.decrypt = function (data) {
        var cipher_data = this.decrypt_rsa(new Buffer(data.payload, 'base64'));
        var cipher_json = JSON.parse(cipher_data);
        var is_valid = this.verify_rsa(cipher_data, data.signature);
        if (is_valid) {
            return cipher_json;
        } else {
            console.log('Invalid RSA signature!');
        }
        return null;
    };

    // Helpers

    GBMCrypto.prototype.sha512 = function (message) {
        const hash = this.crypto.createHash('sha512');
        message = message.replace('\r\n', '\n');
        message = message.replace('\r', '\n');
        hash.update(message);
        return hash.digest('hex');
    };

    GBMCrypto.prototype.random_string = function (len) {
        return this.crypto.randomBytes(len).toString('hex');
    };

    return GBMCrypto;
}());
