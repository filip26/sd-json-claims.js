> [!NOTE]
> 🚧 **Work in Progress** - Feedback of any kind is welcome and contributions are highly appreciated! Feel free to open an issue or submit a pull request.

# SD JSON Claims

Privacy-preserving selective disclosure of JSON claims using [Salted Merkle Tree](https://github.com/filip26/salted-merkle-tree).

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

const root = smt.generateRoot(hmacKey, claims);
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

const disclosure = smt.generatePath(hmacKey, claims, indices);
```

### Verifier

The verifier reconstructs the Merkle root from the disclosed claims and associated disclosure data.

```js
import { extractJSONClaims } from "sd-json-claims";

const { claims } = extractJSONClaims(disclosedDocument);
const { salts, indices, path } = disclosure;

const root = smt.recreateRoot(claims, salts, indices, path);
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
});
```

#### Web Crypto API

```js
import { SaltedMerkleTree } from "sd-json-claims";

const encoder = new TextEncoder();

const smt = new SaltedMerkleTree({
  hash: async (chunks) => {
    const data = concatBytes(chunks);
    return new Uint8Array(
      await crypto.subtle.digest("SHA-256", data)
    );
  },
  hmac: async (key, chunks) => {
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      key,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    return new Uint8Array(
      await crypto.subtle.sign("HMAC", cryptoKey, concatBytes(chunks))
    );
  },
});
```

