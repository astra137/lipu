import { monotonicUlid } from 'https://deno.land/std@0.224.0/ulid/mod.ts'
import { decodeHex } from 'https://deno.land/std@0.224.0/encoding/hex.ts'
import { createFunctions } from '../tokens/encrypted.ts'

const KV_KEY_TOKENS = 't'

type EncryptedToken = {
	me: string
	client_id: string
	scope: string
	nonce: string
}

type DatabaseToken = {
	me: string
	client_id: string
	scope: string
}

async function initialize() {
	// Array.from(crypto.getRandomValues(new Uint8Array(32))).map(x => x.toString(16).padStart(2, '0')).join('')
	const secret = Deno.env.get('TOKEN_SECRET')
	if (!secret) throw new Error('TOKEN_SECRET env var missing!')
	return await createFunctions<EncryptedToken>(decodeHex(secret))
}

const kv = await Deno.openKv()
const { encrypt, decrypt } = await initialize()

export async function createToken(claims: DatabaseToken) {
	const nonce = monotonicUlid()
	const token = await encrypt({ ...claims, nonce })
	await kv.set([KV_KEY_TOKENS, nonce], claims)
	return token
}

export async function verifyToken(token: string) {
	const original = await decrypt(token)
	const result = await kv.get<DatabaseToken>([KV_KEY_TOKENS, original.nonce])
	return {
		...original,
		...result.value,
	}
}
