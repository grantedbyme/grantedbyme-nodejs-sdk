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

    // dependencies

    // https://github.com/request/request
    const request = require('request');
    // console.log('Request module loaded.');

    // https://nodejs.org/api/fs.html
    const fs = require('fs');
    // console.log('FileSystem module loaded.');

    // https://nodejs.org/api/crypto.html
    var crypto;
    try {
        crypto = require('crypto');
        crypto.constants = require('constants');
    } catch (err) {
        console.log('crypto support is disabled!');
        return null;
    }
    // console.log('Crypto module loaded.');

    const gbm_crypto = require('./gbm_crypto');

    // constants

    const VERSION = '1.0.8';
    const BRANCH = 'master';
    const HOST = 'https://api.grantedby.me/v1/service/';
    const USER_AGENT = 'GrantedByMe/' + VERSION + '-' + BRANCH + ' (Node.js)';

    /**
     * Creates a new GrantedByMe SDK instance.
     *
     * @param params {{private_key: String, private_key_path: String, server_key: String, server_key_path: String, api_url: String}}
     * @constructor
     */
    function GrantedByMe(params) {
        this.CHALLENGE_ACCOUNT = 1;
        this.CHALLENGE_SESSION = 2;
        this.CHALLENGE_REGISTER = 4;
        if (params.private_key) {
            this.private_key = params.private_key;
        } else if (params.private_key_path) {
            this.private_key = fs.readFileSync(params.private_key_path, 'utf8');
        } else {
            console.log('Missing private key parameter!');
        }
        if (params.server_key) {
            this.server_key = params.server_key;
        } else if (params.server_key_path) {
            this.server_key = fs.readFileSync(params.server_key_path, 'utf8');
        } else {
            console.log('Missing server key parameter!');
        }
        if (params.api_url) {
            this.api_url = params.api_url;
        } else {
            this.api_url = HOST;
        }
        this.crypto = new gbm_crypto(crypto, this.private_key, this.server_key);
    }

    /**
     * Initiate key exchange for encrypted communication.
     *
     * @param public_key {String} Service RSA public key encoded in PEM format
     * @param callback {Function} The result callback function
     */
    GrantedByMe.prototype.activate_handshake = function (public_key, callback) {
        const params = this.get_params(null, null);
        params.public_key = public_key;
        this.post(params, 'activate_handshake', callback);
    };

    /**
     * Active pending service using service key.
     *
     * @param service_key {String} The activation service key
     * @param callback {Function} The result callback function
     */
    GrantedByMe.prototype.activate_service = function (service_key, callback) {
        // TODO:
        // 1. generate key pair
        // 2. call activate handshake
        // 3. save public key and derive public hash
        const params = this.get_params(null, null);
        params.service_key = service_key;
        this.post(params, 'activate_service', callback);
    };

    /**
     * Links a service user account with a GrantedByMe account.
     *
     * @param challenge {String} The challenge used to verify the user
     * @param authenticator_secret {String} The secret used for user authentication
     * @param callback {Function} The result callback function
     */
    GrantedByMe.prototype.link_account = function (challenge, authenticator_secret, callback) {
        const params = this.get_params(null, null);
        params.challenge = challenge;
        params.authenticator_secret = authenticator_secret;
        this.post(params, 'link_account', callback);
    };

    /**
     * Un-links a service user account with a GrantedByMe account.
     *
     * @param authenticator_secret {String} The secret used for user authentication
     * @param callback {Function} The result callback function
     */
    GrantedByMe.prototype.unlink_account = function (authenticator_secret, callback) {
        const params = this.get_params(null, null);
        params.authenticator_secret = authenticator_secret;
        this.post(params, 'unlink_account', callback);
    };

    /**
     * Returns a challenge with required type.
     *
     * @param challenge_type {Number} The type of requested challenge
     * @param callback {Function} The result callback function
     * @param client_ip {String} The client IP address
     * @param client_ua {String} The client user-agent identifier
     */
    GrantedByMe.prototype.get_challenge = function (challenge_type, callback, client_ip, client_ua) {
        const params = this.get_params(client_ip, client_ua);
        params.challenge_type = challenge_type;
        this.post(params, 'get_challenge', callback);
    };

    /**
     * Returns a challenge state.
     *
     * @param challenge {String} The challenge to check
     * @param callback {Function} The result callback function
     * @param client_ip {String} The client IP address
     * @param client_ua {String} The client user-agent identifier
     */
    GrantedByMe.prototype.get_challenge_state = function (challenge, callback, client_ip, client_ua) {
        const params = this.get_params(client_ip, client_ua);
        params.challenge = challenge;
        this.post(params, 'get_challenge_state', callback);
    };

    /**
     * Notify the GrantedByMe server about the user has been logged out from the service.
     *
     * @param challenge {String}  The challenge representing an active authentication session
     * @param callback {Function} The result callback function
     */
    GrantedByMe.prototype.revoke_challenge = function (challenge, callback) {
        const params = this.get_params(null, null);
        params.challenge = challenge;
        this.post(params, 'revoke_challenge', callback);
    };

    ////////////////////////////////////////
    // Helpers
    ////////////////////////////////////////

    /**
     * Generates a secure random authenticator secret.
     * @returns {String} The secure random authenticator secret
     */
    GrantedByMe.prototype.generate_authenticator_secret = function () {
        return this.crypto.random_string(128);
    };

    /**
     * Generates hash digest of an authenticator secret.
     * @param authenticator_secret The authenticator secret to hash
     * @returns {String} The hashed authenticator secret
     */
    GrantedByMe.prototype.hash_authenticator_secret = function (authenticator_secret) {
        return this.crypto.sha512(authenticator_secret);
    };

    /**
     * Returns the default HTTP parameters.
     *
     * @param client_ip {String} The client IP address
     * @param client_ua {String} The client user-agent identifier
     * @returns {{timestamp: Number, remote_addr: String, http_user_agent: String}}
     */
    GrantedByMe.prototype.get_params = function (client_ip, client_ua) {
        const params = {};
        params.timestamp = new Date().getTime();
        if (client_ip) {
            params.remote_addr = client_ip;
        }
        if (client_ua) {
            params.http_user_agent = client_ua;
        }
        return params;
    };

    /**
     * Sends a HTTP (POST) API request.
     *
     * @param params {Object} The request parameter object
     * @param operation {String} The API operation name
     * @param callback {Function} The result callback function
     */
    GrantedByMe.prototype.post = function (params, operation, callback) {
        const scope = this;
        var body = params;
        if(operation !== 'activate_handshake') {
            body = this.crypto.encrypt(params);
        }
        const options = {
            url: this.api_url + operation + '/',
            headers: {
                'User-Agent': USER_AGENT,
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
            json: true,
            body: body
        };
        request.post(options, function (error, response, body) {
            var decrypted_body = body;
            if (body && body['payload'] && response && operation !== 'activate_handshake') {
                decrypted_body = scope.crypto.decrypt(body);
            }
            callback(error, response, decrypted_body)
        });
    };

    return GrantedByMe;
}());
