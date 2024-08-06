import { assertEquals } from '$std/assert/mod.ts'
import { ulid } from 'jsr:@std/ulid'
import { createFunctions, generateKeys } from './signed.ts'

const JWK: JsonWebKey = {
	kty: 'EC',
	crv: 'P-256',
	x: 'xIfGeZZlKz1xzB7IgJ2DtMMQ3153KEZ2-h_FtKBJsUs',
	y: 'WdtbT_NxCyoSF-QFsMnfI8ly7Bg9sHVLrgJnSrMZyuc',
	d: 'z022LEXVjiX3lHp7lZf5AmEoghjKUBU_AB58lBMzH4E',
}

Deno.test('key length', async () => {
	const key = await generateKeys()
	const jwk = await crypto.subtle.exportKey('jwk', key.privateKey)
	assertEquals(jwk.kty, 'EC')
	assertEquals(jwk.crv, 'P-256')
	assertEquals(jwk.x?.length, 43)
	assertEquals(jwk.y?.length, 43)
	assertEquals(jwk.d?.length, 43)
})

Deno.test('encode then decode claims', async () => {
	type Claims = { iat: number }
	const { encode, decode } = await createFunctions<Claims>(JWK)
	const original = { iat: 1700000000 }
	const token = await encode(original)
	const actual = await decode(token)
	assertEquals(token.length, 103)
	assertEquals(actual, original)
})

Deno.test('encode then decode ulid', async () => {
	const { encode, decode } = await createFunctions<string>(JWK)
	const original = ulid()
	const token = await encode(original)
	const decrypted = await decode(token)
	assertEquals(token.length, 124)
	assertEquals(decrypted, original)
})
