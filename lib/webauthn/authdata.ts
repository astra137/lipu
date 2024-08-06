import { Decoder } from 'https://deno.land/x/cbor@v1.5.9/decode.js'

function decodeCborMapSeq(data: Uint8Array): Array<Map<unknown, unknown>> {
	const decoder = new Decoder({ useRecords: true })
	const seq = decoder.decodeMultiple(data)
	if (seq === undefined) throw new Error()
	for (const map of seq) {
		if (!(map instanceof Map)) {
			throw new Error(`${map}`)
		}
	}
	return seq
}

// https://www.w3.org/TR/webauthn-2/#authenticator-data
//
// [0..     ][32   ][33..     ][37..    ]
// [rpIdHash][flags][signCount][variable]

export function rpIdHash(authData: Uint8Array) {
	return authData.subarray(0, 32)
}

export function flags(authData: Uint8Array) {
	const x = authData[32]
	return {
		up: Boolean(x & (1 << 0)),
		uv: Boolean(x & (1 << 2)),
		be: Boolean(x & (1 << 3)),
		bs: Boolean(x & (1 << 4)),
		at: Boolean(x & (1 << 6)),
		ed: Boolean(x & (1 << 7)),
	}
}

export function signCount(authData: Uint8Array) {
	const dv = new DataView(
		authData.buffer,
		authData.byteOffset,
		authData.byteLength,
	)
	return dv.getUint32(33)
}

export function aaguid(authData: Uint8Array) {
	if (!flags(authData).at) throw new Error()
	return authData.subarray(37, 53)
}

export function credentialId(authData: Uint8Array) {
	if (!flags(authData).at) throw new Error()
	const dv = new DataView(
		authData.buffer,
		authData.byteOffset,
		authData.byteLength,
	)
	const credentialIdLength = dv.getUint16(53)
	return authData.subarray(55, 55 + credentialIdLength)
}

export function credentialAlg(authData: Uint8Array) {
	if (!flags(authData).at) throw new Error()
	const dv = new DataView(
		authData.buffer,
		authData.byteOffset,
		authData.byteLength,
	)
	const credentialIdLength = dv.getUint16(53)
	const credentialCbor = authData.subarray(55 + credentialIdLength)
	const [credentialPublicKey, _extensions] = decodeCborMapSeq(credentialCbor)
	const alg = credentialPublicKey.get(3)
	if (typeof alg === 'number') return alg
	throw new Error('invalid cose key')
}

export function credentialPublicKey(authData: Uint8Array) {
	if (!flags(authData).at) throw new Error()
	const dv = new DataView(
		authData.buffer,
		authData.byteOffset,
		authData.byteLength,
	)
	const credentialIdLength = dv.getUint16(53)
	const credentialCbor = authData.subarray(55 + credentialIdLength)
	const [credentialPublicKey, _extensions] = decodeCborMapSeq(credentialCbor)
	return credentialPublicKey
}

export function extensions(authData: Uint8Array) {
	const { at, ed } = flags(authData)

	if (at) {
		const dv = new DataView(
			authData.buffer,
			authData.byteOffset,
			authData.byteLength,
		)
		const credentialIdLength = dv.getUint16(53)
		const credentialCbor = authData.subarray(55 + credentialIdLength)
		const [_, extensions] = decodeCborMapSeq(credentialCbor)
		return extensions
	}

	if (ed) {
		const extensionsCbor = authData.subarray(37)
		const [extensions] = decodeCborMapSeq(extensionsCbor)
		return extensions
	}
}
