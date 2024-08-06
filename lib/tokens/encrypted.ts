import { concat } from 'https://deno.land/std@0.224.0/bytes/concat.ts'
import * as b64u from 'https://deno.land/std@0.224.0/encoding/base64url.ts'
import * as cbor from 'https://deno.land/x/cbor@v1.5.9/index.js'

const ALG = { name: 'AES-GCM' }

async function importKey(secret: Uint8Array) {
	return await crypto.subtle.importKey('raw', secret, ALG, false, [
		'encrypt',
		'decrypt',
	])
}

async function encrypt(
	key: CryptoKey,
	data: Uint8Array,
	additionalData: Uint8Array,
) {
	const iv = crypto.getRandomValues(new Uint8Array(12))
	const alg = { ...ALG, iv, additionalData }
	const encrypted = await crypto.subtle.encrypt(alg, key, data)
	return concat([iv, new Uint8Array(encrypted)])
}

async function decrypt(
	key: CryptoKey,
	data: Uint8Array,
	additionalData: Uint8Array,
) {
	const iv = data.subarray(0, 12)
	const alg = { ...ALG, iv, additionalData }
	const encrypted = data.subarray(12)
	const decrypted = await crypto.subtle.decrypt(alg, key, encrypted)
	return new Uint8Array(decrypted)
}

export async function createFunctions<T>(
	secret: Uint8Array,
	headerByte = 0x89,
) {
	const key = await importKey(secret)
	return {
		async encrypt(value: T): Promise<string> {
			const msg = cbor.encode(value)
			const aad = new Uint8Array([headerByte])
			const data = await encrypt(key, msg, aad)
			return b64u.encodeBase64Url(concat([aad, data]))
		},
		async decrypt(token: string): Promise<T> {
			const bytes = b64u.decodeBase64Url(token)
			const aad = bytes.subarray(0, 1)
			if (aad[0] !== headerByte) throw new Error('headerByte')
			const data = bytes.subarray(1)
			const msg = await decrypt(key, data, aad)
			return cbor.decode(msg)
		},
	}
}
