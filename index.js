/**
 * @file JSON Web Token
 * @author Rafael Kallis <rk@rafaelkallis.com>
 * @license MIT
 */

'use strict';

const jose = require('node-jose');
const invariant = require('invariant');
const debug = require('debug')('@rk/jwt')

class JWT {

  constructor(secret) {
    invariant(
      secret.length >= 32, 
      'jwt secret must be at least 32 characters long',
    );

    /**
     * json web key (JWK)
     *
     * JWK @see https://tools.ietf.org/html/rfc7517
     * example JWK @see https://tools.ietf.org/html/rfc7517#section-3
     * JWA @see https://tools.ietf.org/html/rfc7518
     * symmetric key JWK @see https://tools.ietf.org/html/rfc7518#section-6.4
     * minimum key sizes @see https://tools.ietf.org/html/rfc7518#section-3.2
     */
    this.jwk = jose.JWK.asKey({
      kty: 'oct',
      k: jose.util.base64url.encode(secret),
    });
    debug('created JWT instance');
  }

  /**
   * Signs the given payload and returns a JWT.
   *
   * @param {Object} payload - The payload to sign.
   * @param {Object} opts - Options @see https://github.com/cisco/node-jose
   * @return {Promise<string>} - A signed json web token.
   */
  async sign(payload, opts = { format: 'compact' }) {
    debug('signing: %j', payload);
    const token = await jose.JWS
      .createSign(opts, await this.jwk)
      .update(Buffer.from(JSON.stringify(payload), 'utf8'))
      .final();
    debug('signed: %s', token);
  }
  
  /**
   * Verifies the given JWS and returns the decoded payload.
   * Rejects if  signature is invalid.
   * @param {string} token - The json web token.
   * @return {Promise<Object>} - The decoded payload.
   */
  async verifySignature (token) {
    debug('verifying signature: %s', token);
    let { payload } = await jose.JWS
      .createVerify(await this.jwk)
      .verify(token);
    payload = JSON.parse(payload.toString('utf8'));
    debug('decoded payload: %j', payload);
    return payload;
  };
  
  /**
   * Encrypts the given payload and returns a JWT.
   * @param {Object} payload - The payload to encrypt.
   * @param {Object} opts - Options @see https://github.com/cisco/node-jose
   * @return {Promise<string>} - An encrypted json web token.
   */
  async encrypt (payload, opts = { format: 'compact' }) {
    debug('encrypting: %j', payload);
    const token = await jose.JWE
      .createEncrypt(opts, await this.jwk)
      .update(Buffer.from(JSON.stringify(payload)))
      .final();
    debug('encrypted token: %s', token);
    return token;
  };
  
  /**
   * Decrypts the given JWE token  and returns the decrypted
   * payload. Rejects if ciphertext is invalid.
   * @param {string} token - The encrypted json web token.
   * @return {Promise<Object>} - The decrypted payload.
   */
  async decrypt (token) {
    debug('decrypting: %s', token);
    let { payload } = await jose.JWE
      .createDecrypt(await jwk)
      .decrypt(token);
    payload =  JSON.parse(payload.toString('utf8'));
    debug('decrypted payload: %j', payload);
    return payload;
  };
}

module.exports = JWT;
