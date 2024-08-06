/// <reference lib="deno.unstable" />

import type { Handler } from '$fresh/server.ts'
import { decodeBase64Url, encodeBase64Url } from '$std/encoding/base64url.ts'
import { getCookies, setCookie } from '$std/http/cookie.ts'
import type { CredentialCreationOptionsJSON } from 'npm:@github/webauthn-json'
import type { PublicKeyCredentialWithAttestationJSON } from 'npm:@github/webauthn-json'
import { monotonicFactory } from 'https://deno.land/x/ulid/mod.ts'
import { createFunctions } from '../../lib/tokens/encrypted.ts'

export type Attestation = PublicKeyCredentialWithAttestationJSON

const ulid = monotonicFactory()

const kv = await Deno.openKv()

type Token = { exp: Date; path: string; data: unknown }
const tokens = await createFunctions<Token>(
	crypto.getRandomValues(new Uint8Array(16)),
)

async function addAttestation(x: Attestation) {
	const expireIn = 3600_000 // 1 hour
	await kv.atomic()
		.set(['at', x.id], x, { expireIn })
		.commit()
}

export async function getAttestation(id: string) {
	const result = await kv.get<Attestation>(['at', id])
	return result.value
}

async function setSideband<T>(
	headers: Headers,
	req: Request,
	maxAge: number,
	data: T,
) {
	const url = new URL(req.url)
	const path = url.pathname
	const value = await tokens.encrypt({
		exp: new Date(Date.now() + maxAge * 1000),
		path,
		data,
	})
	setCookie(headers, {
		name: 'sideband',
		secure: true,
		httpOnly: true,
		sameSite: 'Strict',
		path,
		maxAge,
		value,
	})
}

async function getSideband<T>(req: Request) {
	const url = new URL(req.url)
	const { sideband } = getCookies(req.headers)
	const token = await tokens.decrypt(sideband)
	if (token.path !== url.pathname) return null
	if (token.exp < new Date()) return null
	return token.data as T
}

export const handler: Handler = (req, ctx) => {
	switch (req.method) {
		case 'GET':
			return handleGet(req, ctx)
		case 'POST':
			return handlePost(req, ctx)
		default:
			return Response.json(null, { status: 405 })
	}
}

const handleGet: Handler = (_req, _ctx) => {
	const userId = encodeBase64Url(new Uint8Array([137]))
	// https://github.com/w3c/webauthn/issues/1856
	const challenge = encodeBase64Url(crypto.getRandomValues(new Uint8Array(16)))
	const options: CredentialCreationOptionsJSON = {
		publicKey: {
			challenge,
			rp: {
				name: 'deno-passkey-inspector',
			},
			user: {
				id: userId,
				name: 'test@example.com',
				displayName: 'Test User',
			},
			pubKeyCredParams: [
				{ type: 'public-key', alg: -7 },
				{ type: 'public-key', alg: -259 },
			],
			authenticatorSelection: {
				residentKey: 'required',
				userVerification: 'preferred',
			},
			attestation: 'direct',
			extensions: {
				credProps: true,
			},
		},
	}
	return Response.json(options)
}

const handlePost: Handler = async (req, ctx) => {
	const attestation: PublicKeyCredentialWithAttestationJSON = await req.json()
	await addAttestation(attestation)
	return Response.json({ location: `/at/${attestation.id}` })
}
