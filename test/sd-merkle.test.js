import test from "node:test";
import assert from "node:assert";
import { createHash, createHmac } from "crypto";
import { SaltedMerkleTree, extractJSONClaims } from "../src/index.js";

test("Salted Merkle Tree with injected crypto primitives", () => {

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

    const root = smt.generateRoot(hmacKey, allClaims);
    assert.strictEqual(Buffer.isBuffer(root), true);
    assert.strictEqual(root.length, 32);

    console.log("root", root.toString("hex"))

    const { claims: disclosedClaims, disclosed, indices: disclosedIndices } = extractJSONClaims(
        {
            name: "Filip",
            city: "Prague",
            country: "Czech Republic"
        },
        new Set(["/country", "/city"]));

    const disclosure = smt.generatePath(hmacKey, disclosedClaims, disclosedIndices);

    const { claims } = extractJSONClaims(disclosed);

    const reconstructedRoot = smt.recreateRoot(
        claims, 
        disclosure.salts, 
        disclosure.indices, 
        disclosure.path);

    console.log("ref", reconstructedRoot.toString("hex"))
    assert.deepStrictEqual(reconstructedRoot, root);
});