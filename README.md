> [!NOTE]
> 🚧 **Work in Progress** - Feedback of any kind is welcome and contributions are highly appreciated! Feel free to open an issue or submit a pull request.

# SD JSON Claims

Privacy-preserving selective disclosure of JSON claims using [Salted Merkle Tree](https://github.com/filip26/salted-merkle-tree).

## Examples

### Issuer

The issuer generates a Merkle root from all JSON claims.

```js
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
const { disclosed: disclosedDocument, claims, indices } = extractJSONClaims(data, new Set([
  "/city",
  "/country",
]));

const disclosure = smt.generatePath(hmacKey, claims, indices);
```

### Verifier

The verifier reconstructs the Merkle root from the disclosed claims and associated disclosure data.

```js
const { claims } = extractJSONClaims(disclosedDocument);
const { salts, indices, path } = disclosure;

const root = smt.recreateRoot(claims, salts, indices, path);

```

Verify the issuer's signature, provided by the holder, against the reconstructed root using the issuer's public key.
