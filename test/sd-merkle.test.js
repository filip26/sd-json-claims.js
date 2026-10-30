import test from "node:test";
import assert from "node:assert";
import { createHash, createHmac, webcrypto } from "crypto";
import { SaltedMerkleTree, extractJSONClaims } from "../src/index.js";

test("Node.js crypto primitives", async () => {

    const smt = new SaltedMerkleTree({
        hash: (chunks) => {
            const h = createHash("sha256");
            for (const c of chunks) {
                if (c != null) {
                    h.update(c);
                }
            }
            return h.digest();
        },
        hmac: (key, chunks) => {
            const h = createHmac("sha256", key);
            for (const c of chunks) {
                if (c != null) {
                    h.update(c);
                }
            }
            return h.digest();
        }
    });

    const hmacKey = Buffer.from("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF", "hex");

    const { claims: allClaims } = extractJSONClaims({
        name: "Filip",
        city: "Prague",
        country: "Czech Republic"
    });

    const root = await smt.generateRoot(hmacKey, allClaims);
    console.log("root", root.toString("hex"))

    assert.ok(root instanceof Uint8Array);
    assert.strictEqual(root.length, 32);

    const { claims: disclosedClaims, disclosed, indices: disclosedIndices } = extractJSONClaims(
        {
            name: "Filip",
            city: "Prague",
            country: "Czech Republic"
        },
        new Set(["/country", "/city"]));

    const disclosure = await smt.generatePath(hmacKey, disclosedClaims, disclosedIndices);

    const { claims } = extractJSONClaims(disclosed);

    const reconstructedRoot = await smt.recreateRoot(
        claims,
        disclosure.salts,
        disclosure.indices,
        disclosure.path);

    console.log("ref", reconstructedRoot.toString("hex"))
    assert.deepStrictEqual(reconstructedRoot, root);
});

test("Web Crypto primitive", async () => {

    const smt = new SaltedMerkleTree({
        hash: async (chunks) => {
            // const data = concat(chunks);
            return new Uint8Array(
                await crypto.subtle.digest("SHA-256", Buffer.concat(chunks))
            );
        },
        hmac: async (key, chunks) => {
            return new Uint8Array(
                await crypto.subtle.sign("HMAC", key, Buffer.concat(chunks))
            );
        },
    });

    const _hmacKey = crypto.subtle.importKey(
        "raw",
        Buffer.from("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF", "hex"),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
    );

    const { claims: allClaims } = extractJSONClaims({
        name: "Filip",
        city: "Prague",
        country: "Czech Republic"
    });

    const hmacKey = await _hmacKey;

    const root = await smt.generateRoot(hmacKey, allClaims);
    assert.ok(root instanceof Uint8Array);
    assert.strictEqual(root.length, 32);

    const { claims: disclosedClaims, disclosed, indices: disclosedIndices } = extractJSONClaims(
        {
            name: "Filip",
            city: "Prague",
            country: "Czech Republic"
        },
        new Set(["/country", "/city"]));

    const disclosure = await smt.generatePath(hmacKey, disclosedClaims, disclosedIndices);

    const { claims } = extractJSONClaims(disclosed);

    const reconstructedRoot = await smt.recreateRoot(
        claims,
        disclosure.salts,
        disclosure.indices,
        disclosure.path);

    assert.deepStrictEqual(reconstructedRoot, root);
});