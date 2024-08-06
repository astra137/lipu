import crypto from 'crypto'
import { importJWK } from 'jose'
import CborMap from 'cbor/types/lib/map'
import { AsnEcSignatureFormatter } from '@peculiar/x509'
import { coseAlg, coseCrv, coseKty } from './cose'

/** */
export async function importKey(key: CborMap) {
	const kty = coseKty(key)
	const params = coseAlg(key)

	switch (kty) {
		// TODO: OKP

		case 'EC2': {
			const crv = coseCrv(key).namedCurve
			const x = Buffer.from(key.get(-2)).toString('base64url')
			const y = Buffer.from(key.get(-3)).toString('base64url')
			return await importJWK({ kty: 'EC2', crv, x, y }, params.id)
		}

		case 'RSA': {
			const n = Buffer.from(key.get(-1)).toString('base64url')
			const e = Buffer.from(key.get(-2)).toString('base64url')
			return await importJWK({ kty: 'RSA', n, e }, params.id)
		}

		default:
			throw new Error(`unsupported kty ${kty}`)
	}
}

/** */
export async function verifyCOSE(
	key: CborMap,
	sig: Uint8Array,
	data: Uint8Array,
) {
	const params = coseAlg(key)
	const publicKey = await importKey(key)
	if (!(publicKey instanceof crypto.KeyObject)) throw new Error()

	// Conditionally decode the 'sig' field.
	// ECDSA-based packed attestation/assertion signatures are ASN.1-encoded.
	// https://w3c.github.io/webauthn/#sctn-signature-attestation-types
	if (params.name === 'ECDSA') {
		const ecsigfmt = new AsnEcSignatureFormatter()
		const webSig = ecsigfmt.toWebSignature(params, sig)
		if (!webSig) throw new Error('ECDSA signature decode failure')
		sig = new Uint8Array(webSig)
	}

	const okay = crypto.verify(null, data, publicKey, sig)
	if (!okay) throw new Error('verify failure')
}
