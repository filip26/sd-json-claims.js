import canonicalize from "canonicalize";

/**
 * Extracts all claims from a document object or its JSON string representation,
 * designating the specified JSON pointers as selected, and returns the claims
 * along with the target document (original if full disclosure, or filtered if disclosed is provided).
 *
 * @param {Object|string} document - The document represented as a map or a JSON string.
 * @param {Array<string>|Set<string>} [pointers] - The set of JSON pointers to designate as selected.
 * @returns {Object} An object containing the extracted claims, optional selected indices, and the target document.
 */
export function extractJSONClaims(document, pointers = null) {
    var data = typeof document === "string" ? JSON.parse(document) : document;
    const claims = [];
    const indices = [];

    var disclosed = _flatten(data, "", claims, p => !pointers ? false : pointers.has(p), indices);

    return {
        disclosed: !disclosed ? document : disclosed,
        claims,
        indices,
    };
}

function _flatten(node, path, claims, isSelected, indices) {

    if (node !== null && typeof node === "object") {
        if (Array.isArray(node)) {
            for (let i = 0; i < node.length; i++) {
                _flatten(
                    node[i],
                    path + "/" + i,
                    claims,
                    isSelected(path) ? _ => true : isSelected,
                    indices);
            }
            return
        }

        let map = null;
        const keys = Object.keys(node).sort();
        for (let i = 0; i < keys.length; i++) {
            const key = keys[i];
            const esc = key.replace(/~/g, "~0").replace(/\//g, "~1");

            var value = _flatten(
                node[key],
                path + "/" + esc,
                claims,
                isSelected(path) ? _ => true : isSelected,
                indices);

            if (!!value) {
                if (!map) {
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
