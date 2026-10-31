
const PREFIX_LEAF = new Uint8Array([0x00]);
const PREFIX_NODE = new Uint8Array([0x01]);
const PREFIX_PADDING = new Uint8Array([0x02]);
const PREFIX_INDEX_PADDING = new Uint8Array([0x10]);
const PREFIX_LEVEL_PADDING = new Uint8Array([0x11]);

/**
 * Provides operations for generating salted Merkle tree roots, generating
 * verification paths, and reconstructing roots to verify disclosed claims.
 *
 * Cryptographic operations are injected through the constructor, allowing
 * Node.js crypto, Web Crypto, or custom implementations.
 *
 * The `hash` and `hmac` functions can be synchronous or asynchronous and must
 * return digest bytes as Uint8Array (or a Promise resolving to them).
 * Both functions must be compatible with the tree's expected input format and
 * hashing semantics.
 * 
 * @author Filip Kolařík <filip26@gmail.com> 
 * @see https://github.com/filip26/salted-merkle-tree
 *
 * @param {Object} options Cryptographic configuration.
 * @param {(chunks: Array<Uint8Array|null|undefined>) => Uint8Array} options.hash Hashes the supplied chunks and returns the digest.
 * @param {(key: Uint8Array, chunks: Array<Uint8Array|null|undefined>) => Uint8Array} options.hmac Computes a keyed hash over the supplied chunks and returns the digest.
 * @param {number} [options.maxDepth] Sets maximum allowed tree depth (default: 8, i.e. 2^8 leaves, max 256 claims).
 * @throws {Error}
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
 *   },
 *   maxDepth: 8, // default, 2^8 leaves, max 256 claims
 * });
 *
 * @example
 * // Custom cryptographic implementations can also be supplied.
 * const smt = new SaltedMerkleTree({
 *   hash: customHash,
 *   hmac: customHmac,
 * });
 * 
 */
export class SaltedMerkleTree {
    constructor(options = {}) {

        const { hash, hmac, maxDepth = 8 } = options;

        if (typeof hash !== "function" || typeof hmac !== "function") {
            throw new Error("Both hash and hmac functions must be provided in options.");
        }

        this.hash = hash;
        this.hmac = hmac;
        this.maxDepth = maxDepth;
        this.maxLeaves = 1 << maxDepth;
    }

    /**
     * Computes the root representing the integrity commitment to a collection of
     * claims.
     *
     * @param {*} hmacKey The HMAC secret key.
     * @param {Uint8Array[]} claims The array of claims.
     * @returns {Promise<Uint8Array>} The root byte array of the tree.
     */
    async generateRoot(hmacKey, claims) {

        if (claims.length > this.maxLeaves) {
            throw new Error(`Claims exceed the maximum allowed number of leaves (${this.maxLeaves}).`);
        }

        const salts = await this._salts(hmacKey, claims.length);

        const mapping = this._mapping(salts);

        const leaves = this._leaves(claims, salts, mapping);

        return this._generateRoot(hmacKey, leaves);
    }

    /**
     * Generates the verification path required to authenticate selected claims
     * against a root.
     *
     * @param {*} hmacKey The HMAC key used for path generation.
     * @param {Uint8Array[]} claims The array of claims.
     * @param {number[]} disclosed The ordered array of claim indices to disclose.
     * @returns {Promise<{path: Uint8Array[], salts: Uint8Array[], indices: number[]}>} The disclosure associated with the disclosed claims.
     */
    async generatePath(hmacKey, claims, disclosed) {

        if (claims.length > this.maxLeaves) {
            throw new Error(`Claims exceed the maximum allowed number of leaves (${this.maxLeaves}).`);
        }

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
     * Reconstructs a root from disclosed claims, their salts and original indices,
     * and a verification path.
     * 
     * The reconstructed root can be compared with a trusted root to verify the
     * integrity and positions of the disclosed claims.
     * 
     * @param {Uint8Array[]} claims The disclosed claim data.
     * @param {Uint8Array[]} salts The salts associated with the disclosed claims.
     * @param {number[]} indices The original leaf indices of the disclosed claims.
     * @param {Uint8Array[]} path The verification path in the verification order.
     * @returns {Promise<Uint8Array>} The reconstructed root hash.
     */
    async recreateRoot(claims, salts, indices, path) {

        if (claims.length > this.maxLeaves) {
            throw new Error(`Claims exceed the maximum allowed number of leaves (${this.maxLeaves}).`);
        }

        if (claims.length != salts.length) {
            throw new Error(`Claims length (${claims.length}) must match salts length (${salts.length}).`);
        }

        if (claims.length != indices.length) {
            throw new Error(`Claims length (${claims.length}) must match indices length (${indices.length}).`);
        }

        let mapping = Array.from({ length: indices.length }, (_, i) => i);
        mapping.sort((a, b) => indices[a] - indices[b]);

        let buffer = new Array(claims.length);
        let levelSize = buffer.length;

        // initialize leaves 
        for (let leafIndex = 0; leafIndex < levelSize; leafIndex++) {
            const claimIndex = mapping[leafIndex];  // claim index in the disclosed dataset

            if (indices[claimIndex] > this.maxLeaves) {
                throw new Error(`Leaf index (${indices[claimIndex]}) exceeds maximum allowed index (${this.maxLeaves - 1}).`);
            }

            mapping[leafIndex] = indices[claimIndex];   // set original leaf index
            buffer[leafIndex] = this._hashLeaf(salts[claimIndex], claims[claimIndex]);
        }

        let level = 1;
        let pathIndex = 0;

        while (levelSize > 1 || pathIndex < path.length) {

            if (level > this.maxDepth) {
                throw new Error(`Maximum tree depth (${this.maxDepth}) exceeded during root reconstruction.`);
            }

            let nextLevelSize = 0;

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

                buffer[nextLevelSize] = this._hashNode(left, right);
                mapping[nextLevelSize] = nodeIndex >>> 1;
                nextLevelSize++;
            }

            levelSize = nextLevelSize;
            level++;
        }

        return buffer[0];
    }

    /**
     * Computes the root representing the integrity commitment to a collection of leaf hashes.
     * 
     * The input buffer is modified in place. The initial number of leaves must be even and greater than one.
     * 
     * @param {*} hmacKey The HMAC secret key used for depth-based padding.
     * @param {Uint8Array[]|Promise<Uint8Array>[]} buffer The array of leaf hashes (overridden during computation).
     * @returns {Promise<Uint8Array>} The root byte array of the tree.
     */
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

    /**
     * Generates the verification path required to authenticate selected leaves against a root.
     * 
     * Selected leaves are represented by null entries in the input buffer. 
     * The resulting path contains the hashes needed to reconstruct the root.
     * 
     * The input buffer is modified in place. The initial number of leaves
     * must be even and greater than one.
     * 
     * @param {*} hmacKey The HMAC secret key used for depth-based padding.
     * @param {Uint8Array[]|Promise<Uint8Array>[]} buffer The array of leaf hashes, with selected leaves represented by null (overridden during computation).
     * @returns {Promise<Uint8Array[]>} The verification path hashes in verification order.
     */
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
    * @param {*} hmacKey The HMAC secret key used to derive salts.
    * @param {number} size The number of leaf entries.
    * @returns {Uint8Array[]|Promise<Uint8Array[]>} The generated salts.
    */
    _salts(hmacKey, size) {
        const totalSize = size + (size & 1);
        const result = new Array(totalSize);

        for (let i = 0; i < totalSize; i++) {
            result[i] = this.hmac(hmacKey, [
                PREFIX_INDEX_PADDING,
                toUint32BE(i)
            ]);
        }

        return result.some(item => item instanceof Promise)
            ? Promise.all(result)
            : result;
    }

    /**
     * Determines the slot assigned to each original leaf index using its salt and the salt ordering.
     *
     * The mapping represents the secret-keyed HMAC slot distribution and associates each original 
     * index with its position in the sorted order.
     * 
     * @param {Uint8Array[]} salts The salts associated with the leaf entries.
     * @returns {number[]} The slot assigned to each original index.
     */
    _mapping(salts) {
        const map = Array.from({ length: salts.length }, (_, i) => i);
        map.sort((a, b) => compareHashes(salts[a], salts[b]));
        return map;
    }

    /**
     * Computes salted leaf hashes while omitting selected claims. H(PREFIX_LEAF || SALT || DATA).
     * 
     * The resulting leaves are intended for verification-path generation. Selected
     * entries remain null, allowing the corresponding claims to be withheld
     * while constructing a proof.
     * 
     * @param {Uint8Array[]} claims The claim data.
     * @param {Uint8Array[]} salts The salts associated with the claims, including a padding salt if required.
     * @param {number[]} mapping The mapping from claim positions to leaf positions.
     * @param {number[]} [selected] The sorted indices of claims to omit, or null to include all claims.
     * @returns {Uint8Array[]|Promise<Uint8Array>[]} The leaves for root construction or verification path generation.
     */
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
     * Computes the hash of an internal node. H(PREFIX_NODE || left || right).
     * 
     * The left and right child hashes are ordered inputs; their positions are significant.
     * 
     * @param {Uint8Array} left The left child hash.
     * @param {Uint8Array} right The right child hash.
     * @returns {Uint8Array|Promise<Uint8Array>} The parent hash.
     */
    _hashNode(left, right) {
        return this.hash([
            PREFIX_NODE,
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
     * @param {Uint8Array} salt The salt associated with the claim.
     * @param {Uint8Array[]} [data] The claim data, or null for an empty claim.
     * @returns {Uint8Array|Promise<Uint8Array>} The leaf hash.
     */
    _hashLeaf(salt, data = null) {

        const chunks = [
            PREFIX_LEAF,
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
     * @param {*} hmacKey The HMAC secret key used to derive the padding value.
     * @param {number} level The zero-based tree level.
     * @returns {Promise<Uint8Array>} The padding hash for the specified level.
     */
    async _levelPadding(hmacKey, level) {
        const padding = await this.hmac(hmacKey, [
            PREFIX_LEVEL_PADDING,
            toUint32BE(level)
        ]);

        return this.hash([
            PREFIX_PADDING,
            padding
        ]);
    }
};

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
        throw new Error(`Hash sizes must match. Received ${a.length} and ${b.length} bytes.`);
    }
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) {
            return a[i] < b[i] ? -1 : 1;
        }
    }
    return 0;
}
