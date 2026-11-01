import canonicalize from "canonicalize";

/**
 * Extracts all claims from a document object or its JSON representation,
 * designating the specified JSON pointers as selected, and returns the claims
 * along with the target document (original if full disclosure, or filtered if disclosed is provided).
 *
 * @param {Object|string} document The document represented as a map or a JSON.
 * @param {Set<string>} [selectors] The set of JSON pointers to designate as selected.
 * @returns {{document: Object, claims: Uint8Array[], indices: number[]}} An object containing the extracted claims, optional selected indices, and the disclosed document.
 */
export function extractJSONClaims(document, selectors = null) {

    let data = typeof document === "string" ? JSON.parse(document) : document;

    const claims = [];
    const indices = [];

    let disclosedDocument = _flatten(
        data,
        "",
        claims,
        selectors === null
            ? _ => false
            : p => selectors.has(p),
        indices);

    return {
        document: !disclosedDocument ? document : disclosedDocument,
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
            const escapedKey = key.replace(/~/g, "~0").replace(/\//g, "~1");

            const value = _flatten(
                node[key],
                path + "/" + escapedKey,
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

    claims.push([
        new TextEncoder().encode(path),
        new Uint8Array([0x00]),
        new TextEncoder().encode(canonicalize(node))]);

    return null;
}
