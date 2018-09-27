/**
 * @file JSON Web Token
 * @author Rafael Kallis <rk@rafaelkallis.com>
 * @license MIT
 */

'use strict';

const jose = require('node-jose');

class JWT {

  constructor(secret) {
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
  }

  /**
   * Signs the given payload and returns a JWT.
   *
   * @param {Object} payload - The payload to sign.
   * @param {Object} opts - Options @see https://github.com/cisco/node-jose
   * @return {Promise<string>} - A signed json web token.
   */
  async sign(payload, opts = { format: 'compact' }) {
    return jose.JWS
      .createSign(opts, await this.jwk)
      .update(Buffer.from(JSON.stringify(payload), 'utf8'))
      .final();
  }
  
  /**
   * Verifies the given JWS and returns the decoded payload.
   * Rejects if  signature is invalid.
   * @param {string} token - The json web token.
   * @return {Promise<Object>} - The decoded payload.
   */
  async verifySignature (token) {
    const { payload } = await jose.JWS
      .createVerify(await this.jwk)
      .verify(token);
    return JSON.parse(payload.toString('utf8'));
  };
  
  /**
   * Encrypts the given payload and returns a JWT.
   * @param {Object} payload - The payload to encrypt.
   * @param {Object} opts - Options @see https://github.com/cisco/node-jose
   * @return {Promise<string>} - An encrypted json web token.
   */
  async encrypt (payload, opts = { format: 'compact' }) {
    return jose.JWE
      .createEncrypt(opts, await this.jwk)
      .update(Buffer.from(JSON.stringify(payload)))
      .final();
  };
  
  /**
   * Decrypts the given JWE token  and returns the decrypted
   * payload. Rejects if ciphertext is invalid.
   * @param {string} token - The encrypted json web token.
   * @return {Promise<Object>} - The decrypted payload.
   */
  async decrypt (token) {
    const { payload } = await jose.JWE
      .createDecrypt(await jwk)
      .decrypt(token);
    return JSON.parse(payload.toString('utf8'));
  };
}

module.exports = JWT;
