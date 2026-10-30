
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
     * @param {*} hmacKey The HMAC secret key
     * @param {Uint8Array[]} claims The array of claims
     * @returns {Promise<Uint8Array>} The root byte array of the salted Merkle tree
     */
    async generateRoot(hmacKey, claims) {

        const salts = await this._salts(hmacKey, claims.length);

        const mapping = this._mapping(salts);

        const leaves = this._leaves(claims, salts, mapping);

        return this._generateRoot(hmacKey, leaves);
    }

    /**
     * Generates disclosure data associated with the disclosed claims.
     *
     * @param {*} hmacKey - The HMAC key used for path generation.
     * @param {Uint8Array[]} claims - The array of claims.
     * @param {number[]} disclosed - The origin indices of disclosed claims.
     * @returns {Promise<{path: Uint8Array[], salts: Uint8Array[], indices: number[]}>} The generated path, disclosed salts, and their mapped indices.
     */
    async generatePath(hmacKey, claims, disclosed) {

        const salts = await this._salts(hmacKey, claims.length);

        const mapping = this._mapping(salts);

        const leaves = this._leaves(claims, salts, mapping, disclosed);

        const path = this._generatePath(hmacKey, leaves);

        const disclosedSalts = new Array(disclosed.length);
        const disclosedIndices = new Array(disclosed.length);

        for (let i = 0; i < disclosed.length; i++) {
            disclosedSalts[i] = salts[i];
            disclosedIndices[i] = mapping[disclosed[i]];
        }

        return {
            path: await path,
            salts: disclosedSalts,
            indices: disclosedIndices,
        }
    }

    /**
     * 
     * @param {Uint8Array[]} claims 
     * @param {Uint8Array[]} salts 
     * @param {number[]} indices 
     * @param {Uint8Array[]} path 
     * @returns {Promise<Uint8Array>}
     */
    async recreateRoot(claims, salts, indices, path) {
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
                    right = await buffer[i];

                } else if (i + 1 < levelSize && ((nodeIndex + 1) === mapping[i + 1])) {
                    const siblings = await Promise.all([buffer[i], buffer[i + 1]]);
                    left = siblings[0];
                    right = siblings[1];
                    i++;

                } else {
                    left = await buffer[i];
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

    async _generateRoot(hmacKey, buffer) {
        const depth = 32 - Math.clz32(buffer.length - 1);

        let levelSize = buffer.length;

        for (let level = 0; level < depth; level++) {

            if ((levelSize & 1) === 1) {
                buffer[levelSize] = this._levelPadding(hmacKey, level);
                levelSize++;
            }

            for (let index = 0; index < levelSize; index += 2) {

                const [left, right] = await Promise.all([buffer[index], buffer[index + 1]]);

                buffer[index >>> 1] = this._hashNode(left, right);
            }

            levelSize >>>= 1;
        }

        return buffer[0];
    }

    async _generatePath(hmacKey, buffer) {
        const path = [];
        const depth = 32 - Math.clz32(buffer.length - 1);
        let levelSize = buffer.length;

        for (let level = 0; level < depth; level++) {
            for (let index = 0; index < levelSize; index += 2) {

                const siblings = [buffer[index], buffer[index + 1]];

                if ((index + 1) === levelSize) {
                    siblings[1] = this._levelPadding(hmacKey, level);
                    levelSize++;
                }

                const [left, right] = await Promise.all(siblings);

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
    * @param {*} hmacKey The HMAC secret key used to derive salts
    * @param {number} size The number of leaf entries
    * @returns {Uint8Array[]|Promise<Uint8Array[]>} The generated salts
    */
    _salts(hmacKey, size) {
        const totalSize = size + (size & 1);
        const result = new Array(totalSize);

        for (let i = 0; i < totalSize; i++) {
            result[i] = this.hmac(hmacKey, [
                new Uint8Array([PREFIX_INDEX_PADDING]),
                toUint32BE(i)
            ]);
        }

        return result.some(item => item instanceof Promise)
            ? Promise.all(result)
            : result;
    }

    /**
     * Returns an array of indices sorted by their corresponding salt hashes.
     *
     * @param {Uint8Array[]} salts Array of salt hashes to compare.
     * @returns {number[]} Indices sorted by hash order.
     */
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

    /**
     * 
     * @param {Uint8Array} left 
     * @param {Uint8Array} right 
     * @returns {Uint8Array|Promise<Uint8Array>}
     */
    async _hashNode(left, right) {
        return this.hash([
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
     * @returns {Uint8Array|Promise<Uint8Array>} The leaf hash
     */
    _hashLeaf(salt, data) {

        const chunks = [
            new Uint8Array([PREFIX_LEAF]),
            salt
        ];

        if (data != null) {
            for (const chunk of data) {
                chunks.push(chunk);
            }
        }
        return this.hash(chunks);
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
     * @param {*} hmacKey The HMAC secret key used to derive the padding value
     * @param {number} level The zero-based tree level
     * @returns {Promise<Uint8Array>} The padding hash for the specified level
     */
    async _levelPadding(hmacKey, level) {
        const padding = await this.hmac(hmacKey, [
            new Uint8Array([PREFIX_LEVEL_PADDING]),
            toUint32BE(level)
        ]);

        return this.hash([
            new Uint8Array([PREFIX_PADDING]),
            padding
        ]);
    }
};