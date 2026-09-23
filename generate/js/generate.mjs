#!/usr/bin/env node
// Generates sd-jwt-rust interop fixtures (issuer/holder keys, salts, issuance,
// verified claims) using sd-jwt-js as the reference implementation. Mirrors
// what setup_sd_jwt_python.sh gets "for free" from sd-jwt-python's own
// generate.py, since sd-jwt-js ships no such tool.
//
// Usage: node generate.mjs <testcase-dir> [<testcase-dir> ...]
// Each <testcase-dir> must contain specification.yml, and its parent
// directory must contain settings.yml (see generate/README.md for the format).

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {
    parseEvents,
    eventsToAst,
    CORE_SCHEMA,
    NOT_RESOLVED,
    SCALAR_STYLE,
    load as loadYaml,
} from 'js-yaml';
import {SDJwtInstance, SDJwtGeneralJSONInstance, GeneralJSON} from '@sd-jwt/core';

const SD_TAG = '!sd';
const SIGNING_ALG = 'ES256';

const ISSUER_KEY_PEM_FILE_NAME = 'issuer_key.pem';
const ISSUER_PUBLIC_KEY_PEM_FILE_NAME = 'issuer_public_key.pem';
const HOLDER_KEY_PEM_FILE_NAME = 'holder_key.pem';
const SETTINGS_FILE_NAME = 'settings.yml';
const SPECIFICATION_FILE_NAME = 'specification.yml';
const SALTS_FILE_NAME = 'claims_vs_salts.json';
const SD_JWT_FILE_NAME_TEMPLATE = 'sd_jwt_issuance';
const VERIFIED_CLAIMS_FILE_NAME = 'verified_contents.json';

// ---- YAML: parse to AST so `!sd`-tagged nodes (on map keys or sequence elements) can be told apart from untagged ones.
// js-yaml's high-level `load()` can't do this: it throws on the unregistered `!sd` tag. ----

const scalarTagDefs = CORE_SCHEMA.tags.filter((t) => t.nodeKind === 'scalar');
const implicitScalarDefs = scalarTagDefs.filter((t) => t.implicit);
const scalarTagByName = new Map(scalarTagDefs.map((t) => [t.tagName, t]));

function resolveScalar(node) {
    if (node.style !== SCALAR_STYLE.PLAIN) return node.value; // quoted/block => literal string
    if (node.tag !== SD_TAG) {
        const def = scalarTagByName.get(node.tag);
        if (def) {
            const v = def.resolve(node.value, true, node.tag);
            if (v !== NOT_RESOLVED) return v;
        }
        return node.value;
    }
    // `!sd`-tagged plain scalar: the semantic tag was shadowed by `!sd`, so
    // re-derive it the same way an implicit (untagged) scalar would resolve.
    for (const def of implicitScalarDefs) {
        const v = def.resolve(node.value, false, def.tagName);
        if (v !== NOT_RESOLVED) return v;
    }
    return node.value;
}

function keyString(node) {
    return node.value;
}

function nodeToPlain(node) {
    if (node.kind === 'scalar') return resolveScalar(node);
    if (node.kind === 'sequence') return node.items.map(nodeToPlain);
    if (node.kind === 'mapping') {
        const obj = {};
        for (const {key, value} of node.items) obj[keyString(key)] = nodeToPlain(value);
        return obj;
    }
    throw new Error(`unsupported YAML node kind: ${node.kind}`);
}

// Same as nodeToPlain, but mappings become Maps instead of plain objects.
// Needed specifically for user_claims: a plain-object claim like
// {"42": "x", "null": "y"} silently reorders to put "42" first - JS engines
// enumerate integer-index-like string keys in ascending numeric order ahead
// of all other keys, regardless of insertion order (ECMA-262
// OrdinaryOwnPropertyKeys). That reordering would change which mock salt
// packSorted pairs with which claim, and would reorder a nested object's own
// JSON bytes when it's hashed as a disclosure value - either way producing a
// digest sd-jwt-rust (which iterates a genuinely order-preserving map) never produces.
// A Map's iteration order has no such special case.
function nodeToClaims(node) {
    if (node.kind === 'scalar') return resolveScalar(node);
    if (node.kind === 'sequence') return node.items.map(nodeToClaims);
    if (node.kind === 'mapping') {
        const map = new Map();
        for (const {key, value} of node.items) map.set(keyString(key), nodeToClaims(value));
        return map;
    }
    throw new Error(`unsupported YAML node kind: ${node.kind}`);
}

// Builds an @sd-jwt/core DisclosureFrame from the tagged AST: a key or
// sequence element tagged `!sd` is added to `_sd` at that level; children are
// walked regardless, since nested disclosures can exist under an untagged
// parent (e.g. `arr: [[!sd "a"]]`).
function buildFrame(node) {
    if (node.kind === 'sequence') {
        const frame = {};
        const sd = [];
        node.items.forEach((item, i) => {
            // @sd-jwt/core's array packer checks `sd.includes(i)` with a numeric
            // index (unlike the mapping packer, which checks string keys) - so,
            // unlike mapping/object `_sd` entries, these must stay numbers.
            if (item.tag === SD_TAG) sd.push(i);
            const f = buildFrame(item);
            if (f) frame[i] = f;
        });
        if (sd.length) frame._sd = sd;
        return Object.keys(frame).length ? frame : undefined;
    }
    if (node.kind === 'mapping') {
        const frame = {};
        const sd = [];
        for (const {key, value} of node.items) {
            const k = keyString(key);
            if (key.tag === SD_TAG) sd.push(k);
            const f = buildFrame(value);
            if (f) frame[k] = f;
        }
        if (sd.length) frame._sd = sd;
        return Object.keys(frame).length ? frame : undefined;
    }
    return undefined;
}

function parseYamlAst(text) {
    const events = parseEvents(text, {});
    return eventsToAst(events, {source: text, schema: CORE_SCHEMA})[0].contents;
}

function loadSpecification(dir) {
    const text = fs.readFileSync(path.join(dir, SPECIFICATION_FILE_NAME), 'utf8');
    const root = parseYamlAst(text);
    const field = (name) => root.items.find((i) => keyString(i.key) === name)?.value;

    const userClaimsNode = field('user_claims');
    const claims = userClaimsNode ? nodeToClaims(userClaimsNode) : new Map();
    const frame = userClaimsNode ? buildFrame(userClaimsNode) : undefined;

    const holderDisclosedNode = field('holder_disclosed_claims');
    const holderDisclosedClaims = holderDisclosedNode ? nodeToPlain(holderDisclosedNode) : {};

    const settingsOverrideNode = field('settings_override');

    return {
        claims,
        frame,
        holderDisclosedClaims,
        addDecoyClaims: !!(field('add_decoy_claims') && nodeToPlain(field('add_decoy_claims'))),
        keyBinding: !!(field('key_binding') && nodeToPlain(field('key_binding'))),
        serializationFormat: field('serialization_format')
            ? nodeToPlain(field('serialization_format'))
            : 'compact',
        settingsOverride: settingsOverrideNode ? nodeToPlain(settingsOverrideNode) : undefined,
    };
}

function loadSettings(dir, override) {
    const text = fs.readFileSync(path.join(dir, '..', SETTINGS_FILE_NAME), 'utf8');
    const settings = loadYaml(text, {schema: CORE_SCHEMA});
    // Shallow top-level merge, same as sd-jwt-rust's Settings::from_path_with_override.
    if (override && typeof override === 'object') {
        for (const [k, v] of Object.entries(override)) settings[k] = v;
    }
    return settings;
}

// A `holder_disclosed_claims` value becomes a PresentationFrame leaf/subtree.
// `true` discloses a leaf; a non-empty array/object recurses; everything else
// (false, null, empty array/object, sd-jwt-python's `None`/`{}` idiom) means
// "don't disclose" - matching sd-jwt-rust's holder::select_disclosures, which
// only recognizes Bool(true)/Number/String as "disclose" and non-empty
// Array/Object as "recurse".
function toPresentationFrame(v) {
    if (v === true) return true;
    if (Array.isArray(v)) {
        if (v.length === 0) return false;
        const out = {};
        v.forEach((item, i) => {
            out[i] = toPresentationFrame(item);
        });
        return out;
    }
    if (v !== null && typeof v === 'object') {
        const keys = Object.keys(v);
        if (keys.length === 0) return false;
        const out = {};
        for (const k of keys) out[k] = toPresentationFrame(v[k]);
        return out;
    }
    return false;
}

// ---- Crypto: ES256 signer/verifier/hasher/PEM export via Node's builtin
// crypto, using the exact key material from settings.yml so exported PEMs
// are byte-identical to sd-jwt-python's. ----

function keyObjectFromJwk(jwk) {
    return crypto.createPrivateKey({
        key: {kty: jwk.kty, crv: jwk.crv, d: jwk.d, x: jwk.x, y: jwk.y},
        format: 'jwk',
    });
}

function publicJwkFromJwk(jwk) {
    return {kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y};
}

function signer(privateKey) {
    return (data) =>
        crypto.sign('sha256', Buffer.from(data), {key: privateKey, dsaEncoding: 'ieee-p1363'}).toString('base64url');
}

function verifier(publicKey) {
    return (data, sig) =>
        crypto.verify(
            'sha256',
            Buffer.from(data),
            {key: publicKey, dsaEncoding: 'ieee-p1363'},
            Buffer.from(sig, 'base64url'),
        );
}

// General JSON serialization may carry several issuer signatures (one per
// key); the config only takes a single verifier callback, so try every
// issuer key and accept if any one validates.
function verifierAny(publicKeys) {
    const verifiers = publicKeys.map(verifier);
    return (data, sig) => verifiers.some((v) => v(data, sig));
}

function sha256Hasher(data) {
    return crypto.createHash('sha256').update(Buffer.isBuffer(data) ? data : Buffer.from(data)).digest();
}

function pemPrivate(keyObject) {
    return keyObject.export({type: 'pkcs8', format: 'pem'});
}

function pemPublic(keyObject) {
    return crypto.createPublicKey(keyObject).export({type: 'spki', format: 'pem'});
}

function base64url(bufOrStr) {
    return Buffer.from(bufOrStr).toString('base64url');
}

// JSON.stringify, but serializing Map instances as JSON objects in their
// (genuinely insertion-ordered) iteration order - see nodeToClaims.
function jsonStringify(value) {
    if (value === undefined) return undefined;
    if (value === null || typeof value === 'boolean' || typeof value === 'number' || typeof value === 'string') {
        return JSON.stringify(value);
    }
    if (Array.isArray(value)) {
        return `[${value.map((v) => jsonStringify(v) ?? 'null').join(',')}]`;
    }
    const entries = value instanceof Map ? value.entries() : Object.entries(value);
    const parts = [];
    for (const [k, v] of entries) {
        const sv = jsonStringify(v);
        if (sv === undefined) continue; // matches JSON.stringify dropping undefined-valued properties
        parts.push(`${JSON.stringify(String(k))}:${sv}`);
    }
    return `{${parts.join(',')}}`;
}

// Mirrors sd-jwt-rust's escape_unicode_chars: a disclosure's serialized
// *value* has every genuinely non-ASCII character (anything JSON.stringify
// itself left as raw UTF-8, i.e. not one of its own \n/\"/\uXXXX escapes)
// replaced with a \uXXXX escape, matching sd-jwt-python's `ensure_ascii=True`
// default. Only the value gets this treatment in sd-jwt-rust (disclosure.rs)
// - not the salt or key - so it's applied to just the value's JSON text here.
function escapeNonAsciiJson(jsonText) {
    let out = '';
    for (const ch of jsonText) {
        const code = ch.codePointAt(0);
        if (code <= 0x7f) {
            out += ch;
        } else if (code <= 0xffff) {
            out += `\\u${code.toString(16).padStart(4, '0')}`;
        } else {
            throw new Error(`non-BMP character unsupported by sd-jwt-rust's mock_salts escaping: ${ch}`);
        }
    }
    return out;
}

// Builds one disclosure (RFC 9901 §5.2): `[salt, value]` for an array
// element, `[salt, key, value]` for an object property.
function makeDisclosure(salt, key, value) {
    const valueJson = escapeNonAsciiJson(jsonStringify(value));
    const data = key === undefined ? `["${salt}",${valueJson}]` : `["${salt}",${jsonStringify(key)},${valueJson}]`;
    return base64url(data);
}

// @sd-jwt/core's own `pack()` isn't used for issuance: it processes a
// mapping's children in two full passes (recurse into every sibling's own
// nested frame first, then create every sibling's own disclosure), whereas
// sd-jwt-rust's create_sd_claims_object/create_sd_claims_list interleave
// per-key (recurse into a key's children, then immediately create that key's
// own disclosure, before moving to the next key) and sort each `_sd` digest
// list. Since interop replays the *same* salts through both implementations
// in FIFO order, the salt assigned to a given claim only matches across
// implementations if disclosures are created in the same relative order - so
// packing is reimplemented here to mirror sd-jwt-rust's traversal exactly
// (see src/issuer.rs).
function packSorted(claims, frame, saltGenerator, disclosures) {
    const sd = (frame && frame._sd) || [];
    const decoyCount = (frame && frame._sd_decoy) || 0;

    if (Array.isArray(claims)) {
        const packed = [];
        for (let i = 0; i < claims.length; i++) {
            const subtree = packSorted(claims[i], frame ? frame[i] : undefined, saltGenerator, disclosures);
            if (sd.includes(i)) {
                const encoded = makeDisclosure(saltGenerator(), undefined, subtree);
                disclosures.push(encoded);
                packed.push({'...': base64url(sha256Hasher(encoded))});
            } else {
                packed.push(subtree);
            }
        }
        for (let j = 0; j < decoyCount; j++) {
            packed.push({'...': base64url(sha256Hasher(saltGenerator()))});
        }
        return packed;
    }

    if (claims instanceof Map || (claims !== null && typeof claims === 'object')) {
        const entries = claims instanceof Map ? claims.keys() : Object.keys(claims);
        const get = (key) => (claims instanceof Map ? claims.get(key) : claims[key]);
        // sd-jwt-rust always inserts `_sd` as the object's first key (see
        // create_sd_claims_object), which matters here: this packed object may
        // itself become a disclosure's *value*, and that gets hashed as
        // JSON-serialized bytes - order-sensitive, unlike the final payload
        // comparison (which is structural/order-independent). Reserving the slot
        // up front keeps `_sd` first regardless of insertion order below;
        // jsonStringify drops it if it's left `undefined`. A Map (not a plain
        // object) so an integer-looking claim key ("42") can't silently jump
        // ahead of it too - see nodeToClaims.
        const packed = new Map([['_sd', undefined]]);
        const sdDigests = [];
        for (const key of entries) {
            const subtree = packSorted(get(key), frame ? frame[key] : undefined, saltGenerator, disclosures);
            if (sd.includes(key)) {
                const encoded = makeDisclosure(saltGenerator(), key, subtree);
                disclosures.push(encoded);
                sdDigests.push(base64url(sha256Hasher(encoded)));
            } else {
                packed.set(key, subtree);
            }
        }
        for (let j = 0; j < decoyCount; j++) {
            sdDigests.push(base64url(sha256Hasher(saltGenerator())));
        }
        if (sdDigests.length) {
            sdDigests.sort();
            packed.set('_sd', sdDigests);
        }
        return packed;
    }

    return claims;
}

function packAndSortPayload(claims, frame, saltGenerator) {
    const disclosures = [];
    const payload = packSorted(claims, frame, saltGenerator, disclosures);
    payload.set('_sd_alg', 'sha-256');
    return {payload, disclosures};
}

// ---- Per-testcase generation ----

async function generateOne(dir) {
    const spec = loadSpecification(dir);
    const settings = loadSettings(dir, spec.settingsOverride);

    const issuerJwks = settings.key_settings.issuer_keys;
    const holderJwk = settings.key_settings.holder_key;

    const issuerKeys = issuerJwks.map((jwk) => ({jwk, key: keyObjectFromJwk(jwk)}));
    const holderKey = keyObjectFromJwk(holderJwk);

    fs.writeFileSync(path.join(dir, ISSUER_KEY_PEM_FILE_NAME), pemPrivate(issuerKeys[0].key));
    fs.writeFileSync(path.join(dir, ISSUER_PUBLIC_KEY_PEM_FILE_NAME), pemPublic(issuerKeys[0].key));
    fs.writeFileSync(path.join(dir, HOLDER_KEY_PEM_FILE_NAME), pemPrivate(holderKey));

    const claims = new Map(spec.claims);
    if (!claims.has('iss')) claims.set('iss', settings.identifiers.issuer);
    if (!claims.has('iat')) claims.set('iat', settings.iat);
    if (!claims.has('exp')) claims.set('exp', settings.exp);
    if (spec.keyBinding) claims.set('cnf', {jwk: publicJwkFromJwk(holderJwk)});

    // sd-jwt-rust always adds `_sd_alg`, even with zero disclosures; sd-jwt-js
    // only does when `issue()` gets a (possibly-empty) disclosureFrame object,
    // so `frame` must never be left `undefined` here.
    const frame = spec.frame || {};
    if (spec.addDecoyClaims) {
        frame._sd_decoy = 2;
    }

    const salts = [];
    const saltGenerator = () => {
        const s = crypto.randomBytes(16).toString('base64url');
        salts.push(s);
        return s;
    };

    const kbOptions = spec.keyBinding
        ? {
            kb: {
                payload: {
                    iat: Math.floor(Date.now() / 1000),
                    aud: settings.identifiers.verifier,
                    nonce: settings.key_binding_nonce,
                },
            },
        }
        : undefined;
    const verifyOptions = spec.keyBinding
        ? {expectedKeyBindingAudience: settings.identifiers.verifier, keyBindingNonce: settings.key_binding_nonce}
        : undefined;

    // The root presentation frame must stay an object even when nothing is
    // disclosed - @sd-jwt/core treats a falsy *root* frame as "no filtering"
    // (disclose everything), unlike a falsy frame at any nested position.
    const rawPresentationFrame = toPresentationFrame(spec.holderDisclosedClaims);
    const presentationFrame =
        rawPresentationFrame && typeof rawPresentationFrame === 'object' ? rawPresentationFrame : {};

    const useGeneral = spec.serializationFormat === 'json' && issuerKeys.length > 1;
    const useJson = spec.serializationFormat === 'json';

    let issuedCompact;
    let verifiedPayload;
    let storedContent;

    if (useGeneral) {
        const instance = new SDJwtGeneralJSONInstance({
            hasher: sha256Hasher,
            hashAlg: 'sha-256',
            saltGenerator,
            verifier: verifierAny(issuerKeys.map(({key}) => crypto.createPublicKey(key))),
            kbSigner: signer(holderKey),
            kbSignAlg: SIGNING_ALG,
            kbVerifier: verifier(crypto.createPublicKey(holderKey)),
        });
        const {payload, disclosures} = packAndSortPayload(claims, frame, saltGenerator);
        const encodedPayload = base64url(jsonStringify(payload));
        const signatures = await Promise.all(
            issuerKeys.map(async ({jwk, key}) => {
                const protectedHeader = {alg: SIGNING_ALG, kid: jwk.kid};
                const encodedProtectedHeader = base64url(JSON.stringify(protectedHeader));
                const signature = await signer(key)(`${encodedProtectedHeader}.${encodedPayload}`);
                return {protected: encodedProtectedHeader, signature};
            }),
        );
        const issuedJson = new GeneralJSON({payload: encodedPayload, disclosures, signatures});
        storedContent = JSON.stringify(issuedJson.toJson());

        const presented = await instance.present(issuedJson, presentationFrame, kbOptions);
        const verified = await instance.verify(presented, {
            ...verifyOptions,
            allowedIssuerAlgorithms: [SIGNING_ALG],
        });
        verifiedPayload = verified.payload;
    } else {
        // signer/signAlg aren't set here: issuance is packed and signed by hand
        // above (packAndSortPayload et al.), never through instance.issue().
        const instance = new SDJwtInstance({
            hasher: sha256Hasher,
            hashAlg: 'sha-256',
            saltGenerator,
            verifier: verifier(crypto.createPublicKey(issuerKeys[0].key)),
            kbSigner: signer(holderKey),
            kbSignAlg: SIGNING_ALG,
            kbVerifier: verifier(crypto.createPublicKey(holderKey)),
        });
        const {payload, disclosures} = packAndSortPayload(claims, frame, saltGenerator);
        // Not using the Jwt/SDJwt classes here: Jwt.sign() JSON.stringifies the
        // payload itself (breaking on our Map payload - see jsonStringify), and
        // SDJwt.encodeSDJwt() expects Disclosure class instances (calls .encode()
        // on each) rather than the encoded strings packSorted already returns.
        const encodedHeader = base64url(JSON.stringify({alg: SIGNING_ALG}));
        const encodedPayload = base64url(jsonStringify(payload));
        const signature = await signer(issuerKeys[0].key)(`${encodedHeader}.${encodedPayload}`);
        issuedCompact = [`${encodedHeader}.${encodedPayload}.${signature}`, ...disclosures, ''].join('~');
        storedContent = useJson
            ? JSON.stringify(instance.toFlattenJSON(issuedCompact).toJson())
            : issuedCompact;

        const presented = await instance.present(issuedCompact, presentationFrame, kbOptions);
        const verified = await instance.verify(presented, verifyOptions);
        verifiedPayload = verified.payload;
    }

    const sdJwtFileName = useJson ? `${SD_JWT_FILE_NAME_TEMPLATE}.json` : `${SD_JWT_FILE_NAME_TEMPLATE}.txt`;
    fs.writeFileSync(path.join(dir, sdJwtFileName), storedContent);
    fs.writeFileSync(path.join(dir, SALTS_FILE_NAME), JSON.stringify(salts, null, 2));
    fs.writeFileSync(path.join(dir, VERIFIED_CLAIMS_FILE_NAME), JSON.stringify(verifiedPayload, null, 2));

    console.log(`generated ${dir}`);
}

async function main() {
    const dirs = process.argv.slice(2);
    if (dirs.length === 0) {
        console.error('Usage: node generate.mjs <testcase-dir> [<testcase-dir> ...]');
        process.exit(1);
    }
    for (const dir of dirs) {
        try {
            await generateOne(path.resolve(dir));
        } catch (err) {
            console.error(`FAILED ${dir}: ${err.stack || err}`);
            process.exitCode = 1;
        }
    }
}

main();
