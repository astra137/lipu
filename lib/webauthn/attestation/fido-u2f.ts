import cbor from 'cbor'
import ow from 'ow'
import * as X509 from '@peculiar/x509'
import { Crypto } from '@peculiar/webcrypto'
import { decodeAuthData } from '../authdata'

const crypto = new Crypto()
X509.cryptoProvider.set(crypto)

const owU2FAttestation = ow.object.exactShape({
	fmt: ow.string.oneOf(['fido-u2f'] as const),
	authData: ow.uint8Array,
	attStmt: ow.object.exactShape({
		sig: ow.uint8Array,
		x5c: ow.array.ofType(ow.uint8Array).length(1),
	}),
})

export async function verifyU2F(
	attestationObject: Uint8Array,
	clientDataHash: Uint8Array,
) {
	// https://www.w3.org/TR/2019/REC-webauthn-1-20190304/#fido-u2f-attestation

	// 1.
	const att = cbor.decode(attestationObject)
	ow(att, owU2FAttestation)
	const { attStmt, authData } = att
	const { rpIdHash, attestedCredentialData } = decodeAuthData(authData)
	ow(attestedCredentialData, ow.object)
	const { credentialId, credentialPublicKey } = attestedCredentialData

	// 2.

	const attCert = new X509.X509Certificate(attStmt.x5c[0])
	// TODO: node-friendly way of extracting the PK?
	const certPK = await attCert.publicKey.export()
	console.debug(certPK)

	// 3.

	// 4.

	const x: Uint8Array = credentialPublicKey.get(-2)
	const y: Uint8Array = credentialPublicKey.get(-3)
	if (x.byteLength !== 32) throw new Error('x malformed')
	if (y.byteLength !== 32) throw new Error('y malformed')
	const publicKeyU2F = Buffer.concat([new Uint8Array([0x04]), x, y], 65)

	// 5.

	const verificationData = Buffer.concat([
		new Uint8Array([0x00]),
		rpIdHash,
		clientDataHash,
		credentialId,
		publicKeyU2F,
	])

	// 6.

	const alg = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' }
	const ecsigfmt = new X509.AsnEcSignatureFormatter()
	const webSig = ecsigfmt.toWebSignature(alg, attStmt.sig)
	if (!webSig) throw new Error('ECDSA signature decode failure')
	const sig = new Uint8Array(webSig)

	const ok = await crypto.subtle.verify(alg, certPK, sig, verificationData)
	if (!ok) throw new Error('invalid signature')

	// 7.

	// 8.

	return {
		type: 'basic' as const,
		path: [attCert],
	}
}
