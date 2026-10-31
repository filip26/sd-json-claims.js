import test from "node:test";
import assert from "node:assert";
import { createHash, createHmac } from "crypto";
import { SaltedMerkleTree, extractJSONClaims, concatUint8Arrays } from "../src/index.js";

test("Node.js crypto primitives", async () => {

    const smt = new SaltedMerkleTree({
        hash: (chunks) => {
            const h = createHash("sha256");
            for (const c of chunks) {
                h.update(c);
            }
            return h.digest();
        },
        hmac: (key, chunks) => {
            const h = createHmac("sha256", key);
            for (const c of chunks) {
                h.update(c);
            }
            return h.digest();
        }
    });

    const hmacKey = Buffer.from("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF", "hex");

    const { claims: allClaims, document } = extractJSONClaims({
        name: "Filip",
        city: "Prague",
        country: "Czech Republic"
    });

    const root = await smt.generateRoot(hmacKey, allClaims);
    console.log("root", root.toString("hex"))

    assert.ok(root instanceof Uint8Array);
    assert.strictEqual(root.length, 32);

    const { claims: disclosedClaims, document: disclosedDocument, indices: disclosedIndices } = extractJSONClaims(
        document,
        new Set(["/country", "/city"]));

    const disclosure = await smt.generatePath(hmacKey, disclosedClaims, disclosedIndices);

    const { claims } = extractJSONClaims(disclosedDocument);

    const ref = await smt.recreateRoot(
        claims,
        disclosure.salts,
        disclosure.indices,
        disclosure.path);

    console.log("ref", ref.toString("hex"))

    assert.ok(ref instanceof Uint8Array);
    assert.strictEqual(ref.length, 32);

    assert.deepStrictEqual(ref, root);
});

test("Web Crypto primitive", async () => {

    const smt = new SaltedMerkleTree({
        hash: async (chunks) => {
            return new Uint8Array(
                await crypto.subtle.digest("SHA-256", concatUint8Arrays(chunks))
            );
        },
        hmac: async (key, chunks) => {
            return new Uint8Array(
                await crypto.subtle.sign("HMAC", key, concatUint8Arrays(chunks))
            );
        },
        maxDepth: 2,
    });

    const _hmacKey = crypto.subtle.importKey(
        "raw",
        Buffer.from("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF", "hex"),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
    );

    const { claims: allClaims, document } = extractJSONClaims({
        name: "Filip",
        city: "Prague",
        country: "Czech Republic"
    });

    const hmacKey = await _hmacKey;

    const root = await smt.generateRoot(hmacKey, allClaims);
    assert.ok(root instanceof Uint8Array);
    assert.strictEqual(root.length, 32);

    const { claims: disclosedClaims, document: disclosedDocument, indices: disclosedIndices } = extractJSONClaims(
        document,
        new Set(["/country", "/city"]));

    const disclosure = await smt.generatePath(hmacKey, disclosedClaims, disclosedIndices);

    const { claims } = extractJSONClaims(disclosedDocument);

    const ref = await smt.recreateRoot(
        claims,
        disclosure.salts,
        disclosure.indices,
        disclosure.path);

    assert.ok(ref instanceof Uint8Array);
    assert.strictEqual(ref.length, 32);

    assert.deepStrictEqual(ref, root);
});