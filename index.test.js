/**
 * @file jwt tests
 * @author Rafael Kallis <rk@rafaelkallis.com>
 * @license MIT
 */

const JWT = require('./index');

describe("JWT", () => {
  let jwt;

  beforeEach(() => {
    jwt = new JWT('1234566789 123456789 123456789 12');
  });

  it('should fail to instantiate on keys with < 32 chars', () => {
    jwt = new JWT('1234566789 123456789 123456789 1');
  });

  it('should sign the payload', async () => {
    expect(await jwt.sign({ sub: 123 })).toEqual(
      'eyJhbGciOiJIUzI1NiIsImtpZCI6InRwelpDdDNVNzU3RVltbE9GUmQzSkltMk10OUY3cTFncFZ3YlhGWV9nOEEifQ.eyJzdWIiOjEyM30.UuQHsTbDBFAB5KVtYaI7KrFw5UhlrITWn2NLEUe2ruM',
    );
  });

  it('should verify the token signature', async () => {
    expect(
      await jwt.verifySignature(
        'eyJhbGciOiJIUzI1NiIsImtpZCI6InRwelpDdDNVNzU3RVltbE9GUmQzSkltMk10OUY3cTFncFZ3YlhGWV9nOEEifQ.eyJzdWIiOjEyM30.UuQHsTbDBFAB5KVtYaI7KrFw5UhlrITWn2NLEUe2ruM',
      ),
    ).toEqual({ sub: 123 });
  });

  it('should encrypt the payload', async () => {
    expect(await jwt.encrypt({ sub: 123 })).toEqual(expect.any(String));
  });

  it('should decrypt the token', async () => {
    expect(
      await jwt.decrypt(
        'eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiUEJFUzItSFMyNTYrQTEyOEtXIiwia2lkIjoidHB6WkN0M1U3NTdFWW1sT0ZSZDNKSW0yTXQ5RjdxMWdwVndiWEZZX2c4QSIsInAycyI6Imh5S3NMMVFiWmVTckF0d3lCNGJqZlEiLCJwMmMiOjgxOTJ9.vmHqPCDewFPwNs7GXIzNGjCr5PbFjCj58mkaPfZ9nG-tHM--OA3Qfw.8C94R_jzCjBC8C4ojf-Pug.dXVjfmWUNDWh5J0XlWEjqA.iPGFV13z6dlvKAdbvgLCdQ',
      ),
    ).toEqual({ sub: 123 });
  });
});
