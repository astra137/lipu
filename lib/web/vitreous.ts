// import Buffer from 'buffer';
// import b64u from 'b64u';
// console.log(b64u.encode(Buffer.alloc(32)));
// 23.1 KiB bundle

// import { toBase64 } from 'fast-base64/js';
// import { toUrl } from 'fast-base64/url';
// console.log(toUrl(toBase64(new Uint8Array(32))));
// 768 Byte bundle

import { toBase64, toBytes } from 'fast-base64/js'
import { toUrl } from 'fast-base64/url'

/** HMAC with SHA-256, using 128-bit keys, implemented via the Web Crypto API */
async function signChain(k: Promise<ArrayBuffer>, m: BufferSource) {
	let alg: HmacImportParams = { name: 'HMAC', hash: 'SHA-256', length: 32 }
	let key = await crypto.subtle.importKey('raw', await k, alg, false, ['sign'])
	let sig = await crypto.subtle.sign(alg, key, m)
	return sig
}

/** Macaroon-like nested, chained signing */
async function refract(lux: ArrayBuffer, ...facets: BufferSource[]) {
	return await facets.reduce(signChain, Promise.resolve(lux))
}

function bytes(x: BufferSource) {
	return ArrayBuffer.isView(x)
		? new Uint8Array(x.buffer, x.byteOffset, x.byteLength)
		: new Uint8Array(x, 0, x.byteLength)
}

//
//
//

/** */
export function dop(gem: string) {
	return gem.split('.').map((x) => toBytes(x))
}

/** */
export function lap(...facets: BufferSource[]) {
	return facets.map((x) => toUrl(toBase64(bytes(x)))).join('.')
}

/** */
export async function sign(secret: ArrayBuffer, ...facets: BufferSource[]) {
	const sig = await refract(secret, ...facets)
	return lap(sig, ...facets)
}

/** */
export async function verify(secret: ArrayBuffer, gem: string) {
	const [actual, ...facets] = dop(gem)
	const expect = await refract(secret, ...facets)
	if (lap(actual) !== lap(expect)) throw new Error('flaw')
	return facets
}

/** */
export async function delegate(gem: string, ...facets: BufferSource[]) {
	const prevSig = dop(gem.slice(0, 64))[0]
	const nextSig = await refract(prevSig, ...facets)
	return [lap(nextSig), gem.slice(65), lap(...facets)].join('.')
}
