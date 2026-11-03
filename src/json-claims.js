import canonicalize from "canonicalize";

const textEncoder = new TextEncoder();
const EMPTY_CLAIM = new Uint8Array([0x00]);

/**
 * Extracts claims from a JSON document and optionally discloses selected
 * JSON Pointer locations.
 *
 * Each undisclosed scalar value produces a claim consisting of:
 * [UTF-8(JSON Pointer), 0x00, UTF-8(canonical JSON value)]
 *
 * Object properties are traversed in lexicographical order to ensure
 * deterministic claim ordering.
 *
 * @param {Object|string} document The document or its JSON representation.
 * @param {Set<string>|null} [selectors=null] JSON Pointers identifying values to disclose.
 * @returns {{ document: Object, claims: (Uint8Array[]|null)[], indices: number[]}} The disclosed document, extracted claims, and selected claim indices.
 */
export function extractJSONClaims(document, selectors = null) {

    const data = typeof document === "string" ? JSON.parse(document) : document;

    if (data === null || typeof data !== "object") {
        throw new TypeError("The document must be a non-null JSON object or array.");
    }

    if (selectors !== null && !(selectors instanceof Set)) {
        throw new TypeError("Selectors must be a Set or null.");
    }

    const claims = [];
    const indices = [];

    const disclosedDocument = _flatten(
        data,
        "",
        claims,
        (selectors === null || selectors.size === 0)
            ? _ => false
            : p => selectors.has(p),
        indices);

    return {
        document: disclosedDocument !== null ? disclosedDocument : data,
        claims,
        indices,
    };
}

function _flatten(node, path, claims, isSelected, indices) {

    if (node === null || node === undefined) {
        throw new Error(`Null or undefined values are not allowed as a JSON claim value at path "${path}", got ${node}.`);
    }

    if (typeof node === "object") {

        if (Array.isArray(node)) {

            if (node.length === 0) {
                throw new Error(`Empty JSON arrays are not allowed as a JSON claim value at path "${path}", got ${node}.`);
            }

            if (isSelected(path)) {
                const result = [];
                for (let i = 0; i < node.length; i++) {
                    result.push(_flatten(
                        node[i],
                        path + "/" + i,
                        claims,
                        _ => true,
                        indices));
                }
                return result;
            }

            let result = null;

            for (let i = 0; i < node.length; i++) {
                const element = _flatten(
                    node[i],
                    path + "/" + i,
                    claims,
                    isSelected,
                    indices);

                if (element !== null) {
                    if (result === null) {
                        result = {};
                    }
                    result[String(i)] = element;
                }
            }
            return result;
        }

        if (node.length === 0) {
            throw new Error(`Empty JSON objects are not allowed as a JSON claim value at path "${path}", got ${node}.`);
        }

        let map = null;
        const keys = Object.keys(node).sort();
        for (let i = 0; i < keys.length; i++) {
            const key = keys[i];

            const value = _flatten(
                node[key],
                path + "/" + _escapePointer(key),
                claims,
                isSelected(path) ? _ => true : isSelected,
                indices);

            if (value !== null) {
                if (map === null) {
                    map = {};
                }
                map[key] = value;
            }
        }
        return map;
    }

    if (isSelected(path)) {
        indices.push(claims.length);
        claims.push(null);
        return node;
    }

    const canonicalValue = canonicalize(node);

    if (canonicalValue === undefined) {
        throw new TypeError(`Unsupported JSON value at path "${path}".`);
    }

    claims.push([
        textEncoder.encode(path),
        EMPTY_CLAIM,
        textEncoder.encode(canonicalize(canonicalValue))]);

    return null;
}

/**
 * Escapes a JSON Pointer reference token (RFC 6901).
 *
 * @param {string} token
 * @returns {string}
 */
function _escapePointer(token) {
    return token.replace(/~/g, "~0").replace(/\//g, "~1");
}