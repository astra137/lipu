/** */
export function coseKty(key: Map<unknown, unknown>) {
	const kty = Number(key.get(1))
	const type = COSE_KEY_TYPES.get(kty)
	if (!type) throw new Error(`unknown kty: ${kty}`)
	return type
}

/** */
export function coseAlg(key: Map<unknown, unknown>) {
	const alg = Number(key.get(3))
	const params = COSE_ALGORITHMS.get(alg)
	if (!params) throw new Error(`unknown alg: ${alg}`)
	return params
}

/** */
export function coseCrv(key: Map<unknown, unknown>) {
	const crv = Number(key.get(-1))
	const curve = COSE_ELLIPTIC_CURVES.get(crv)
	if (!curve) throw new Error(`unknown crv: ${crv}`)
	return curve
}

/** https://www.iana.org/assignments/cose/cose.xhtml#key-types */
const COSE_KEY_TYPES = new Map([
	[1, 'OKP'],
	[2, 'EC2'],
	[3, 'RSA'],
	[4, 'Symmetric'],
	[5, 'HSS-LMS'],
	[6, 'WalnutDSA'],
])

/** https://www.iana.org/assignments/cose/cose.xhtml#algorithms */
const COSE_ALGORITHMS = new Map([
	[-259, { id: 'RS512', name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' }],
	[-258, { id: 'RS384', name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' }],
	[-257, { id: 'RS256', name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }],

	[-47, { id: 'ES256K', name: 'ECDSA', namedCurve: 'K-256', hash: 'SHA-256' }],

	[-44, { name: 'SHA-512' }],
	[-43, { name: 'SHA-384' }],

	[-39, { id: 'PS512', name: 'RSA-PSS', hash: 'SHA-512' }],
	[-38, { id: 'PS384', name: 'RSA-PSS', hash: 'SHA-384' }],
	[-37, { id: 'PS256', name: 'RSA-PSS', hash: 'SHA-256' }],

	[-36, { id: 'ES512', name: 'ECDSA', namedCurve: 'P-521', hash: 'SHA-512' }],
	[-35, { id: 'ES384', name: 'ECDSA', namedCurve: 'P-384', hash: 'SHA-384' }],

	[-16, { name: 'SHA-256' }],

	[-8, { id: 'EdDSA', name: 'EdDSA', namedCurve: 'Ed25519', hash: 'SHA-256' }],

	[-7, { id: 'ES256', name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' }],
	// ECDH ???
])

/** https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves */
const COSE_ELLIPTIC_CURVES = new Map([
	[1, { kty: 'EC2', namedCurve: 'P-256', id: 'secp256r1' }],
	[2, { kty: 'EC2', namedCurve: 'P-384', id: 'secp384r1' }],
	[3, { kty: 'EC2', namedCurve: 'P-521', id: 'secp521r1' }],
	[4, { kty: 'OKP', namedCurve: 'X25519' }],
	[5, { kty: 'OKP', namedCurve: 'X448' }],
	[6, { kty: 'OKP', namedCurve: 'Ed25519' }],
	[7, { kty: 'OKP', namedCurve: 'Ed448' }],
	[8, { kty: 'EC2', namedCurve: 'K-256', id: 'secp256k1' }],
])
