import { DBSchema, openDB } from 'idb'
import { dop, lap } from 'lib/web/vitreous'

interface BobaSchema extends DBSchema {
	keys: {
		key: string
		value: CryptoKey
	}
}

async function openBobaDB() {
	return await openDB<BobaSchema>('boba', 1, {
		upgrade(db, oldVersion, newVersion, transaction) {
			db.createObjectStore('keys')
		},
	})
}

//
//
//

const concat = (...parts: BufferSource[]) => new Blob(parts).arrayBuffer()

function shrink(jwk: JsonWebKey): JsonWebKey {
	const { kty, crv, n, e, x, y } = jwk
	switch (kty) {
		case 'EC':
			return { crv, kty, x, y }
		case 'RSA':
			return { e, kty, n }
		default:
			throw new Error(kty)
	}
}

async function thumbprint(jwk: JsonWebKey) {
	const text = JSON.stringify(shrink(jwk))
	const data = new TextEncoder().encode(text)
	const hash = await crypto.subtle.digest('SHA-256', data)
	return lap(hash)
}

async function generateKeyPair() {
	try {
		// Elliptic curve is preferred for small key size.
		return await crypto.subtle.generateKey(
			{
				name: 'ECDSA',
				namedCurve: 'P-256',
				hash: 'SHA-256',
			},
			false,
			['sign', 'verify'],
		)
	} catch (err) {}

	try {
		// RSA is kinda sus ngl, but Edge has incomplete WebCrypto.
		return await crypto.subtle.generateKey(
			{
				name: 'RSASSA-PKCS1-v1_5',
				modulusLength: 4096,
				publicExponent: new Uint8Array([1, 0, 1]),
				hash: 'SHA-256',
			},
			false,
			['sign', 'verify'],
		)
	} catch (err) {}

	throw new Error('keygen failed')
}

//
async function signChallenge(kid: string, key: CryptoKey) {
	const resp = await fetch('/api/boba/challenge', { method: 'POST' })
	if (!resp.ok) throw new Error(resp.statusText)
	const challenge = await resp.arrayBuffer()
	const nonce = crypto.getRandomValues(new Uint8Array(18))
	const blob = await concat(challenge, nonce)
	const opt = { ...key.algorithm, hash: 'SHA-256' }
	const sig = await crypto.subtle.sign(opt, key, blob)
	return lap(...dop(kid), challenge, nonce, sig)
}

//
//
//

/** */
export async function bobaCreate(authorization: string) {
	// NOTE: As a part of the change to VS Code built-in library definitions,
	// TypeScript suddenly thinks the keys might be undefined.
	// Does this imply that MS Edge keygen could fail without throwing?
	const { privateKey, publicKey } = await generateKeyPair()
	if (!(privateKey instanceof CryptoKey)) throw new Error()
	if (!(publicKey instanceof CryptoKey)) throw new Error()

	const jwk = shrink(await crypto.subtle.exportKey('jwk', publicKey))
	const sid = await thumbprint(jwk)
	const token = await signChallenge(sid, privateKey)
	const resp = await fetch('/api/boba/response', {
		method: 'POST',
		headers: { authorization, 'Content-Type': 'application/json' },
		body: JSON.stringify({ jwk, token }),
	})
	if (!resp.ok) throw new Error(resp.statusText)

	const db = await openBobaDB()
	await db.put('keys', privateKey, sid)
	db.close()
	return sid
}

/** */
export async function bobaSession() {
	const db = await openBobaDB()
	const [sid] = await db.getAllKeys('keys', null, 1)
	db.close()
	return sid ? sid : null
}

/** */
export async function bobaToken(sid: string) {
	const db = await openBobaDB()
	const privateKey = await db.get('keys', sid)
	if (!privateKey) throw new Error()
	const token = await signChallenge(sid, privateKey!)
	db.close()
	return token
}

/** */
export async function bobaDelete(sid: string) {
	const token = await bobaToken(sid)
	const res = await fetch('/api/boba/response', {
		method: 'DELETE',
		headers: { authorization: `BOBA ${token}` },
	})

	const db = await openBobaDB()
	await db.delete('keys', sid)
	db.close()

	if (!res.ok && res.status !== 401) {
		throw new Error(res.statusText)
	}
}
