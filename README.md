## JWT


```sh
npm install --save @rafaelkallis/jwt
```


#### Import & Initialization

```js
const JWT = require('@rafaelkallis/jwt');

// secret must be at least 32 charactes long
const jwt = new JWT('secret');
```

#### Signing
Signs the given payload and returns a JWT.

```js
const token = await jwt.sign({ sub: 123 });
```


#### Verify Signature
Verifies the given JWT and returns the decoded payload.
Rejects if the signature is invalid.

```js
const payload = await jwt.verifySignature(token);
```


#### Encrypt
Encrypts the given payload and returns a JWT.

```js
const token = await jwt.encrypt({ sub: 123 });
```


#### Decrypt
Decrypts the given JWT and returns the decrypted payload.
Rejects if the ciphertext is invalid.
```js
const payload = await jwt.decrypt(token);
```
