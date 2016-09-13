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
    } catch (err) {
        console.log('crypto support is disabled!');
        return null;
    }
    // console.log('Crypto module loaded.');

    const gbm_crypto = require('./gbm_crypto');

    // constants

    const VERSION = '1.0.4';
    const BRANCH = 'master';
    const HOST = 'https://api.grantedby.me/v1/service/';
    const USER_AGENT = 'GrantedByMe/' + VERSION + '-' + BRANCH + ' (Node.js)';

    // constructor

    function GrantedByMe(params) {
        if (params.private_key) {
            this.private_key = private_key;
        } else if (params.private_key_path) {
            this.private_key = fs.readFileSync(params.private_key_path, 'utf8');
        } else {
            console.log('Missing private key parameter!');
        }
        if (params.server_key) {
            this.server_key = server_key;
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

    // api

    GrantedByMe.prototype.activate_handshake = function (public_key, client_ip, client_ua) {
        var params = this.get_params(client_ip, client_ua);
        this.post(params, 'activate_handshake', callback);
    };

    GrantedByMe.prototype.activate_service = function (service_key, client_ip, client_ua) {
        var params = this.get_params(client_ip, client_ua);
        this.post(params, 'activate_service', callback);
    };

    GrantedByMe.prototype.deactivate_service = function (callback, client_ip, client_ua) {
        var params = this.get_params(client_ip, client_ua);
        this.post(params, 'deactivate_service', callback);
    };

    GrantedByMe.prototype.link_account = function (token, grantor, callback, client_ip, client_ua) {
        var params = this.get_params(client_ip, client_ua);
        params.token = token;
        params.grantor = grantor;
        this.post(params, 'link_account', callback);
    };

    GrantedByMe.prototype.unlink_account = function (grantor, callback, client_ip, client_ua) {
        var params = this.get_params(client_ip, client_ua);
        params.grantor = this.crypto.sha512(grantor);
        this.post(params, 'unlink_account', callback);
    };

    GrantedByMe.prototype.get_account_token = function (callback, client_ip, client_ua) {
        this.get_token(1, callback, client_ip, client_ua);
    };

    GrantedByMe.prototype.get_session_token = function (callback, client_ip, client_ua) {
        this.get_token(2, callback, client_ip, client_ua);
    };

    GrantedByMe.prototype.get_register_token = function (callback, client_ip, client_ua) {
        this.get_token(4, callback, client_ip, client_ua);
    };

    GrantedByMe.prototype.get_token = function (type, callback, client_ip, client_ua) {
        var params = this.get_params(client_ip, client_ua);
        params.token_type = type;
        this.post(params, 'get_session_token', callback);
    };

    GrantedByMe.prototype.get_token_state = function (token, callback, client_ip, client_ua) {
        var params = this.get_params(client_ip, client_ua);
        params.token = token;
        this.post(params, 'get_session_state', callback);
    };

    GrantedByMe.prototype.revoke_session_token = function (token, callback, client_ip, client_ua) {
        var params = this.get_params(client_ip, client_ua);
        params.token = token;
        this.post(params, 'revoke_session_token', callback);
    };

    // helpers

    GrantedByMe.prototype.get_params = function (client_ip, client_ua) {
        var params = {};
        params.timestamp = new Date().getTime();
        if (client_ip) {
            params.remote_addr = client_ip;
        } else {
            params.remote_addr = '0.0.0.0';
        }
        if (client_ua) {
            params.http_user_agent = client_ua;
        } else {
            params.http_user_agent = 'Unknown';
        }
        return params;
    };

    GrantedByMe.prototype.post = function (params, operation, callback) {
        var scope = this;
        var options = {
            url: this.api_url + operation + '/',
            headers: {
                'User-Agent': USER_AGENT,
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
            json: true,
            body: this.crypto.encrypt(params)
        };
        return request.post(options, function (error, response, body) {
            var decrypted_body = body;
            if (response && body) {
                decrypted_body = scope.crypto.decrypt(body);
            }
            callback(error, response, decrypted_body)
        });
    };

    return GrantedByMe;
}());
