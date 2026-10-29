
const PREFIX_LEAF = 0x00;
const PREFIX_NODE = 0x01;
const PREFIX_PADDING = 0x02;
const PREFIX_INDEX_PADDING = 0x10;
const PREFIX_LEVEL_PADDING = 0x11;

function toUint32BE(num) {
    return new Uint8Array([
        num >>> 24,
        (num >>> 16) & 0xff,
        (num >>> 8) & 0xff,
        num & 0xff
    ]);
}

function compareHashes(a, b) {
    if (a.length !== b.length) {
        throw new Error("The hash sizes are not the same.");
    }
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) {
            return a[i] < b[i] ? -1 : 1;
        }
    }
    return 0;
}

/**
 * Provides operations for generating salted Merkle tree roots, generating
 * verification paths, and reconstructing roots to verify disclosed claims.
 *
 * Cryptographic operations are injected through the constructor, allowing
 * Node.js crypto, Web Crypto, @noble/hashes, or custom implementations.
 *
 * The `hash` and `hmac` functions must return digest bytes as a Buffer or
 * Uint8Array. Both functions must be compatible with the tree's expected
 * input format and hashing semantics.
 *
 * @see https://github.com/filip26/salted-merkle-tree
 *
 * @param {Object} options - Cryptographic configuration.
 * @param {(chunks: Array<Uint8Array|null|undefined>) => Uint8Array} options.hash Hashes the supplied chunks and returns the digest.
 * @param {(key: Uint8Array, chunks: Array<Uint8Array|null|undefined>) => Uint8Array} options.hmac Computes a keyed hash over the supplied chunks and returns the digest.
 * @throws {Error} If either `hash` or `hmac` is not a function.
 *
 * @example
 * // Node.js crypto
 * import { createHash, createHmac } from "node:crypto";
 * import { SaltedMerkleTree } from "sd-json-claims";
 *
 * const smt = new SaltedMerkleTree({
 *   hash: (chunks) => {
 *     const h = createHash("sha256");
 *     for (const chunk of chunks) {
 *       if (chunk != null) h.update(chunk);
 *     }
 *     return h.digest();
 *   },
 *   hmac: (key, chunks) => {
 *     const h = createHmac("sha256", key);
 *     for (const chunk of chunks) {
 *       if (chunk != null) h.update(chunk);
 *     }
 *     return h.digest();
 *   }
 * });
 *
 * @example
 * // Custom cryptographic implementations can also be supplied.
 * const smt = new SaltedMerkleTree({
 *   hash: customHash,
 *   hmac: customHmac
 * });
 */
export class SaltedMerkleTree {
    constructor(options = {}) {

        const { hash, hmac } = options;

        if (typeof hash !== "function" || typeof hmac !== "function") {
            throw new Error("Both hash and hmac functions must be provided in options.");
        }

        this.hash = hash;
        this.hmac = hmac;
    }

    /**
     * Computes the root representing the integrity commitment to a collection of
     * claims.
     *
     * @param {Uint8Array|string} hmacKey The HMAC secret key
     * @param {Uint8Array[]} claims The array of claims
     * @returns {Uint8Array} The root byte array of the salted Merkle tree
     */
    generateRoot(hmacKey, claims) {

        const salts = this._salts(hmacKey, claims.length);

        const mapping = this._mapping(salts);

        const leaves = this._leaves(claims, salts, mapping);

        return this._generateRoot(hmacKey, leaves);
    }

    generatePath(hmacKey, claims, disclosed) {

        const salts = this._salts(hmacKey, claims.length);

        const mapping = this._mapping(salts);

        const leaves = this._leaves(claims, salts, mapping, disclosed);

        const path = this._generatePath(hmacKey, leaves);

        const disclosedSalts = [];
        const disclosedIndices = [];

        for (let i=0; i < disclosed.length; i++) {
            disclosedSalts[i] = salts[i];
            disclosedIndices[i] = mapping[disclosed[i]];
        }

        return {
            path,
            salts: disclosedSalts,
            indices: disclosedIndices,
        }
    }

    recreateRoot(claims, salts, indices, path) {
        let mapping = Array.from({ length: indices.length }, (_, i) => i);
        mapping.sort((a, b) => indices[a] - indices[b]);

        let buffer = new Array(claims.length);
        let levelSize = buffer.length;

        for (let i = 0; i < levelSize; i++) {
            const mappedIdx = mapping[i];
            buffer[i] = this._hashLeaf(salts[mappedIdx], claims[mappedIdx]);
            mapping[i] = indices[mappedIdx];
        }

        let pathIndex = 0;

        while (levelSize > 1 || pathIndex < path.length) {
            let nextLevelSize = 0;
            const nextBuffer = [];
            const nextMapping = [];

            for (let i = 0; i < levelSize; i++) {
                const nodeIndex = mapping[i];
                let left, right;

                if ((nodeIndex & 1) === 1) {
                    left = path[pathIndex++];
                    right = buffer[i];
                } else if (i + 1 < levelSize && ((nodeIndex + 1) === mapping[i + 1])) {
                    left = buffer[i];
                    right = buffer[i + 1];
                    i++;
                } else {
                    left = buffer[i];
                    right = path[pathIndex++];
                }

                nextBuffer[nextLevelSize] = this._hashNode(left, right);
                nextMapping[nextLevelSize] = nodeIndex >>> 1;
                nextLevelSize++;
            }

            buffer = nextBuffer;
            mapping = nextMapping;
            levelSize = nextLevelSize;
        }

        return buffer[0];
    }

    _hash(chunks) {
        return this.hash(chunks);
    }

    _hmac(key, chunks) {
        return this.hmac(key, chunks);
    }

    _generateRoot(hmacKey, buffer) {
        const depth = 32 - Math.clz32(buffer.length - 1);

        let levelSize = buffer.length;

        for (let level = 0; level < depth; level++) {

            if ((levelSize & 1) === 1) {
                buffer[levelSize] = this._levelPadding(hmacKey, level);
                levelSize++;
            }

            for (let index = 0; index < levelSize; index += 2) {
                buffer[index >>> 1] = this._hashNode(
                    buffer[index],
                    buffer[index + 1]);
            }

            levelSize >>>= 1;
        }

        return buffer[0];
    }

    _generatePath(hmacKey, buffer) {
        const path = [];
        const depth = 32 - Math.clz32(buffer.length - 1);
        let levelSize = buffer.length;

        for (let level = 0; level < depth; level++) {
            for (let index = 0; index < levelSize; index += 2) {

                const left = buffer[index];
                let right;

                if ((index + 1) === levelSize) {
                    right = this._levelPadding(hmacKey, level);
                    levelSize++;
                } else {
                    right = buffer[index + 1];
                }

                let parent = null;

                if (left === null) {

                    if (right !== null) {
                        path.push(right);
                    }

                } else if (right === null) {
                    path.push(left);

                } else {
                    parent = this._hashNode(left, right);
                }

                buffer[index >>> 1] = parent;
            }

            levelSize >>>= 1;
        }

        return path;
    }

    /**
    * Generates salts for leaf entries, including an additional salt when required
    * to accommodate an odd number of entries.
    * 
    * Salts are derived using the supplied HMAC secret key and an index-dependent input.
    *
    * @param {Uint8Array|string} hmacKey The HMAC secret key used to derive salts
    * @param {number} size The number of leaf entries
    * @returns {Uint8Array[]} The generated salts
    */
    _salts(hmacKey, size) {
        const totalSize = size + (size & 1);
        const result = new Array(totalSize);

        for (let i = 0; i < totalSize; i++) {
            result[i] = this._hmac(hmacKey, [
                new Uint8Array([PREFIX_INDEX_PADDING]),
                toUint32BE(i)
            ]);
        }
        return result;
    }

    _mapping(salts) {
        const map = Array.from({ length: salts.length }, (_, i) => i);
        map.sort((a, b) => compareHashes(salts[a], salts[b]));
        return map;
    }

    _leaves(claims, salts, mapping, selected = null) {

        const remainder = claims.length & 1;
        const buffer = new Array(claims.length + remainder);
        let selectedIndex = 0;

        for (let i = 0; i < claims.length; i++) {
            if (selected == null || selectedIndex >= selected.length || selected[selectedIndex] !== i) {
                buffer[mapping[i]] = this._hashLeaf(salts[i], claims[i]);
            } else {
                selectedIndex++;
                buffer[mapping[i]] = null;
            }
        }

        if (remainder > 0) {
            buffer[mapping[claims.length]] = this._hashLeaf(salts[claims.length], null);
        }

        return buffer;
    }

    _hashNode(left, right) {
        return this._hash([
            new Uint8Array([PREFIX_NODE]),
            left,
            right
        ]);
    }

    /**
     * Computes the hash representing a salted leaf claim.
     *
     * Including a salt helps protect low-entropy claim data against offline
     * dictionary attacks.
     * 
     * @param {Uint8Array} salt The salt associated with the claim
     * @param {Uint8Array} data The claim data, or null for an empty claim
     * @returns {Uint8Array} The leaf hash
     */
    _hashLeaf(salt, data) {
        const chunks = [new Uint8Array([PREFIX_LEAF]), salt];
        if (data != null) {
            for (const chunk of data) {
                chunks.push(chunk);
            }
        }
        return this._hash(chunks);
    }

    /**
     * Derives the padding hash used for a missing sibling at a specified tree
     * level.
     * 
     * H(PREFIX_PADDING || HMAC(K, PREFIX_LEVEL_PADDING || uint32_be(level)))
     *
     * Level-specific padding allows incomplete levels to be handled without
     * explicitly materializing all padding nodes.
     *
     * @param {Uint8Array|string} hmacKey The HMAC secret key used to derive the padding value
     * @param {Number} level The zero-based tree level
     * @returns {Uint8Array} The padding hash for the specified level
     */
    _levelPadding(hmacKey, level) {
        const padding = this._hmac(hmacKey, [
            new Uint8Array([PREFIX_LEVEL_PADDING]),
            toUint32BE(level)
        ]);

        return this._hash([
            new Uint8Array([PREFIX_PADDING]),
            padding
        ]);
    }
};