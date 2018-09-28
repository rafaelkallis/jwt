/**
 * @file jwt tests
 * @author Rafael Kallis <rk@rafaelkallis.com>
 * @license MIT
 */

const JWT = require('./index');

describe("JWT", () => {
  let jwt;

  beforeEach(() => {
    jwt = new JWT('123456789 123456789 123456789 12');
  });

  it('should fail to instantiate on keys with < 32 chars', () => {
    expect(() => new JWT('123456789 123456789 123456789 1')).toThrow();
  });

  it('should sign the payload', async () => {
    expect(await jwt.sign({ sub: 123 })).toEqual(
      'eyJhbGciOiJIUzI1NiIsImtpZCI6Im5jazZVRHlYM19wdnpwSldZQW1QQjdrMG5XdjhhdkhRak83cU5laHBWZVkifQ.eyJzdWIiOjEyM30.a4RXENt60jgscVslIHj-5ybKX4MEe3ZSEuHzC9Suwec',
    );
  });

  it('should verify the token signature', async () => {
    expect(
      await jwt.verify(
        'eyJhbGciOiJIUzI1NiIsImtpZCI6Im5jazZVRHlYM19wdnpwSldZQW1QQjdrMG5XdjhhdkhRak83cU5laHBWZVkifQ.eyJzdWIiOjEyM30.a4RXENt60jgscVslIHj-5ybKX4MEe3ZSEuHzC9Suwec',
      ),
    ).toEqual({ sub: 123 });
  });

  it('should encrypt the payload', async () => {
    expect(await jwt.encrypt({ sub: 123 })).toEqual(expect.any(String));
  });

  it('should decrypt the token', async () => {
    expect(
      await jwt.decrypt(
        'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiQTI1NktXIiwia2lkIjoibmNrNlVEeVgzX3B2enBKV1lBbVBCN2swbld2OGF2SFFqTzdxTmVocFZlWSJ9.gtQ54_Q0pKl_EekcT3I5_FZwj7jY9DGa90ntwbkJYgrHz3qiavAWvA.WGW4A-I6GaGAFKZITPUPUA.drPFMAoPzCT2NRc5lnQvXw.HApW_eJRQVDHEF90dFYifQ',
      ),
    ).toEqual({ sub: 123 });
  });
});
