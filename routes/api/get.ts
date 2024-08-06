import type { Handler } from '$fresh/server.ts'
import { decodeBase64Url, encodeBase64Url } from '$std/encoding/base64url.ts'
import { deleteCookie, getCookies, setCookie } from '$std/http/cookie.ts'
import type { CredentialRequestOptionsJSON } from 'npm:@github/webauthn-json'
import type { PublicKeyCredentialWithAssertionJSON } from 'npm:@github/webauthn-json'
import { getAttestation } from './create.ts'

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

const handleGet: Handler = (req, _ctx) => {
	const url = new URL(req.url)
	const challenge = encodeBase64Url(crypto.getRandomValues(new Uint8Array(32)))
	const options: CredentialRequestOptionsJSON = {
		publicKey: {
			challenge,
			// rpId: 'localhost',
			// allowCredentials: []
			// userVerification: 'required'
			timeout: 120_000,
		},
	}
	const headers = new Headers()
	setCookie(headers, {
		name: 'csrf',
		value: challenge,
		secure: true,
		httpOnly: true,
		sameSite: 'Strict',
		path: url.pathname,
		maxAge: 300,
	})
	return Response.json(options, { headers })
}

const handlePost: Handler = async (req, ctx) => {
	const assertion: PublicKeyCredentialWithAssertionJSON = await req.json()

	const { csrf } = getCookies(req.headers)
	const { challenge } = JSON.parse(
		new TextDecoder().decode(
			decodeBase64Url(assertion.response.clientDataJSON),
		),
	)

	if (challenge !== csrf) {
		return Response.json({ error: 'csrf' }, { status: 400 })
	}

	const attestation = await getAttestation(assertion.id)

	if (!attestation) {
		return Response.json({ error: 'key not found' }, { status: 400 })
	}

	// TODO
	console.log(assertion)
	console.log(attestation)

	return Response.json({ location: `/assertions/${challenge}` })
}
