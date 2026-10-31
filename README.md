> [!NOTE]
> 🚧 **Work in Progress** - Feedback of any kind is welcome and contributions are highly appreciated! Feel free to open an issue or submit a pull request.

# SD JSON Claims

Privacy-preserving selective disclosure of JSON documents using [Salted Merkle Tree](https://github.com/filip26/salted-merkle-tree). 

A JSON document is transformed into an ordered sequence of claims that are signed by an issuer. The signature tethered with the origin document is passed to a holder, which is a disclosing party having the ability to select a particular set of claims to be disclosed and shared as a JSON document with a verifier. The verifier does not receive all the claims included in the origin document, only the disclosed claims, and can verify the disclosed document fragment is the one signed by the issuer while undisclosed claims stay secret.

Selective disclosure is used in a three-party model allowing a verifier to validate a trusted issuer signature without interacting with the issuer, ensuring unlinkability and untraceability.

## Three-party trust model

1. Issuer: Generates cryptographic commitment to data, ensuring authenticity and integrity through digital signing.
2. Holder: Manages selective disclosure, choosing specific claims to reveal while preserving the immutable issuer signature.
3. Verifier: Validates the authenticity and integrity of the disclosed subset against the trusted issuer signature without requiring interaction with the issuer.

## Examples

### Issuer

The issuer generates a Merkle root from all JSON claims.

```js
import { extractJSONClaims } from "sd-json-claims";

const { claims } = extractJSONClaims({
  name: "Filip",
  city: "Prague",
  country: "Czech Republic",
});

const root = await smt.generateRoot(hmacKey, claims);
```

The issuer signs the root using asynchronous cryptography, then shares the signature and HMAC key with the holder.

### Holder (Disclosing Party)

The disclosing party selects claims to disclose and generates the corresponding disclosure data.

```js
import { extractJSONClaims } from "sd-json-claims";

const { disclosed: disclosedDocument, claims, indices } = extractJSONClaims(
  data,
  new Set([
    "/city",
    "/country",
  ])
);

const disclosure = await smt.generatePath(hmacKey, claims, indices);
```

The disclosed document and its associated disclosure data:

```json
{
  "city": "Prague",
  "country": "Czech Republic"
}
```
```javascript
{
  salts: [
    ...
  ],
  path: [
    ...
  ],
  indices: [0, 2],
  signature: Sig(root)
}
```

### Verifier

The verifier reconstructs the Merkle root from the disclosed claims and associated disclosure data.

```js
import { extractJSONClaims } from "sd-json-claims";

const { claims } = extractJSONClaims(disclosedDocument);
const { salts, indices, path } = disclosure;

const root = await smt.recreateRoot(claims, salts, indices, path);
```

Verify the issuer's signature, provided by the holder, against the reconstructed root using the issuer's public key.

### Initialization

Initialize `SaltedMerkleTree` with SHA-256 hashing and HMAC-SHA-256. Choose the implementation for your runtime.

#### Node.js

```js
import { createHash, createHmac } from "node:crypto";
import { SaltedMerkleTree } from "sd-json-claims";

const smt = new SaltedMerkleTree({
  hash: (chunks) => {
    const h = createHash("sha256");
    for (const c of chunks) {
      if (c != null) h.update(c);
    }
    return h.digest();
  },
  hmac: (key, chunks) => {
    const h = createHmac("sha256", key);
    for (const c of chunks) {
      if (c != null) h.update(c);
    }
    return h.digest();
  },
  maxDepth: 8,  // default, 2^8 leaves, max 256 claims
});
```

#### Web Crypto API

```js
import { SaltedMerkleTree } from "sd-json-claims";

const smt = new SaltedMerkleTree({
  hash: async (chunks) => {
    return new Uint8Array(
      await crypto.subtle.digest("SHA-256", concatBytes(chunks))
    );
  },
  hmac: async (key, chunks) => {
    return new Uint8Array(
      await crypto.subtle.sign("HMAC", key, concatBytes(chunks))
    );
  },
  maxDepth: 8,  // default, 2^8 leaves, max 256 claims
});

const hmacSecretKey = await crypto.subtle.importKey(
      "raw",
      rawKey,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
```



