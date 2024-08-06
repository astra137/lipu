import { Buffer } from 'buffer'
import cbor from 'cbor'
import ow from 'ow'
import * as X509 from '@peculiar/x509'
import { Crypto } from '@peculiar/webcrypto'
import { verifyCOSE } from '../crypto'
import { decodeAuthData } from '../authdata'

const crypto = new Crypto()
X509.cryptoProvider.set(crypto)

const owPackedAttestation = ow.object.exactShape({
	fmt: ow.string.oneOf(['packed'] as const),
	authData: ow.uint8Array,
	attStmt: ow.object.exactShape({
		alg: ow.number,
		sig: ow.uint8Array,
		x5c: ow.optional.array.ofType(ow.uint8Array),
	}),
})

// Information:
// https://w3c.github.io/webauthn/#sctn-packed-attestation
// https://w3c.github.io/webauthn/#ref-for-verification-procedure%E2%91%A6

export async function verifyPacked(
	attestationObject: Uint8Array,
	clientDataHash: Uint8Array,
) {
	// ==========================================================================
	// 1. Extract fields

	const att = cbor.decode(attestationObject)
	ow(att, owPackedAttestation)
	const { authData, attStmt } = att
	const { attestedCredentialData } = decodeAuthData(authData)
	if (!attestedCredentialData) throw new Error()
	const { aaguid, credentialPublicKey } = attestedCredentialData
	const verificationData = Buffer.concat([authData, clientDataHash])

	// ==========================================================================
	// 2. If x5c is present, one of 3 attestation types are in use

	if (attStmt.x5c) {
		const x5c = attStmt.x5c.map((x) => new X509.X509Certificate(x))
		const attestnCert = x5c[0]

		// - sig is valid signature
		const certPK = await attestnCert.publicKey.export()
		const ok = await crypto.subtle.verify(
			certPK.algorithm,
			certPK,
			attStmt.sig,
			verificationData,
		)
		if (!ok) throw new Error('invalid signature')

		// - attestnCert meets requirements
		// https://w3c.github.io/webauthn/#sctn-packed-attestation-cert-requirements
		// TODO finish this
		const subject = new X509.Name(attestnCert.subject).toJSON()
		const ou = subject.find(
			(x) => x['OU'] && x['OU'][0] === 'Authenticator Attestation',
		)
		if (!ou) throw new Error(`OU !== 'Authenticator Attestation'`)

		// - If attestnCert contains an extension for aaguid
		const aaguidExt = attestnCert.getExtension('id-fido-gen-ce-aaguid')
		console.debug('id-fido-gen-ce-aaguid', aaguidExt)
		if (aaguidExt) {
			if (!Buffer.from(aaguidExt.value).equals(aaguid)) {
				throw new Error('id-fido-gen-ce-aaguid !== aaguid')
			}
			if (aaguidExt.critical) {
				throw new Error('id-fido-gen-ce-aaguid must not be critical')
			}
		}

		const bce = attestnCert.getExtension(X509.BasicConstraintsExtension)
		if (bce && bce.ca) {
			throw new Error('Basic Constraints CA must be false')
		}

		//TODO AIA extension?

		// - Inspect x5c to determine whether attStmt conveys Basic or AttCA attestation
		// skipped

		// - Return attestion type and trust path
		return {
			type: 'basic' as const,
			path: x5c,
		}
	}

	// ==========================================================================
	// 3. If x5c is not present, self attestation is in use...

	// - alg matches credentialPublicKey
	if (attStmt.alg !== credentialPublicKey.get(3)) {
		throw new Error('expected attestation alg to match credential')
	}

	// - sig is valid signature
	await verifyCOSE(credentialPublicKey, attStmt.sig, verificationData)

	// - Return attestation type self and empty trust path
	return {
		type: 'self' as const,
		path: [],
	}
}
