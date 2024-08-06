import { assertEquals } from '$std/assert/mod.ts'
import { ulid } from 'jsr:@std/ulid'
import { createFunctions } from './encrypted.ts'

// const JWK = { kty: 'oct', k: '4ZHPUMzAqgMnoEfFRjMI7Q' }

Deno.test('encode then decode claims', async () => {
	const secret = crypto.getRandomValues(new Uint8Array(16))
	type Data = { iat: number }
	const { encrypt, decrypt } = await createFunctions<Data>(secret)
	const original = { iat: 1700000000, tmp: true }
	const token = await encrypt(original)
	const actual = await decrypt(token)
	assertEquals(token.length, 62)
	assertEquals(actual, original)
})

Deno.test('encode then decode ulid', async () => {
	const secret = crypto.getRandomValues(new Uint8Array(16))
	const { encrypt, decrypt } = await createFunctions<string>(secret)
	const original = ulid()
	const token = await encrypt(original)
	const actual = await decrypt(token)
	assertEquals(token.length, 76)
	assertEquals(actual, original)
})
