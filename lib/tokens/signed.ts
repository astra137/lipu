import { concat } from 'https://deno.land/std@0.224.0/bytes/concat.ts'
import * as b64u from 'https://deno.land/std@0.224.0/encoding/base64url.ts'
import * as cbor from 'https://deno.land/x/cbor@v1.5.9/index.js'

const ALG = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' }

export async function generateKeys() {
	return await crypto.subtle.generateKey(
		ALG,
		true,
		['sign', 'verify'],
	)
}

async function sign(key: CryptoKey, data: Uint8Array) {
	const signature = await crypto.subtle.sign(ALG, key, data)
	return new Uint8Array(signature)
}

async function verify(key: CryptoKey, sig: Uint8Array, data: Uint8Array) {
	return await crypto.subtle.verify(ALG, key, sig, data)
}

export async function createFunctions<T>(
	jwk: JsonWebKey,
	headerByte = 0x89,
) {
	const privateKey = await crypto.subtle.importKey(
		'jwk',
		{ ...jwk, key_ops: ['sign'] },
		ALG,
		false,
		['sign'],
	)

	const publicKey = await crypto.subtle.importKey(
		'jwk',
		{ ...jwk, d: undefined, key_ops: ['verify'] },
		ALG,
		false,
		['verify'],
	)

	const encode = async (value: T): Promise<string> => {
		const header = new Uint8Array([headerByte])
		const payload = cbor.encode(value)
		const msg = concat([header, payload])
		const sig = await sign(privateKey, msg)
		if (sig.length !== 64) throw new Error('invariant')
		return b64u.encodeBase64Url(concat([msg, sig]))
	}

	const decode = async (token: string): Promise<T> => {
		const bytes = b64u.decodeBase64Url(token)
		const len = bytes.byteLength
		const msg = bytes.subarray(0, len - 64)
		const sig = bytes.subarray(len - 64, len)
		const header = msg.subarray(0, 1)
		if (header[0] !== headerByte) throw new Error('invalid token')
		const payload = msg.subarray(1)
		const ok = await verify(publicKey, sig, msg)
		if (!ok) throw new Error('invalid token')
		return cbor.decode(payload)
	}

	return { encode, decode }
}
