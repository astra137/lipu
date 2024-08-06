import { createHash } from 'crypto'
import cbor from 'cbor'
import ow from 'ow'
import { decodeX5C, verifyCompactJWS } from '../pki'

const owAndroidSafetyNetAttestation = ow.object.exactShape({
	fmt: ow.string.oneOf(['android-safetynet'] as const),
	authData: ow.uint8Array,
	attStmt: ow.object.exactShape({
		ver: ow.string,
		response: ow.uint8Array,
	}),
})

const owSafetyNetResponse = ow.object.exactShape({
	timestampMs: ow.number,
	// Data provided by the calling app
	nonce: ow.string,
	// Data about the calling app
	apkPackageName: ow.string,
	apkDigestSha256: ow.string,
	apkCertificateDigestSha256: ow.array.ofType(ow.string),
	// Integrity verdict
	ctsProfileMatch: ow.boolean,
	basicIntegrity: ow.boolean,
	// Optional fields
	advice: ow.optional.string,
	error: ow.optional.string,
	evaluationType: ow.optional.string,
})

/**
 * Android SafetyNet Attestation Statement Verification
 *
 * https://w3c.github.io/webauthn/#sctn-key-attstn-cert-requirements
 */
export async function verifyAndroidSafetyNet(
	attestationObject: Uint8Array,
	clientDataHash: Uint8Array,
) {
	const decoded = cbor.decode(attestationObject)
	ow(decoded, owAndroidSafetyNetAttestation)
	const { attStmt, authData, fmt } = decoded

	const { ver, response } = attStmt
	if (typeof ver !== 'string') throw new Error()
	if (!(response instanceof Uint8Array)) throw new Error()
	const jws = new TextDecoder('utf-8').decode(response)

	// Verify the SafetyNet response authenticity
	// Verify that response is a valid SafetyNet response
	// https://developer.android.com/training/safetynet/attestation#compat-check-response

	const json = await verifyCompactJWS(jws, 'attest.android.com')
	const snr = JSON.parse(new TextDecoder('utf-8').decode(json))

	ow(snr, owSafetyNetResponse)

	if (snr.error) throw new Error(snr.error)

	if (Date.now() - snr.timestampMs > 600_000) {
		// TODO: I have no idea how long this should be
		throw new Error('Android SafetyNet: response is more than 10min old')
	}

	if (!snr.ctsProfileMatch) {
		throw new Error('Android SafetyNet: device failed CTS')
	}

	// Verify that the nonce equals Base64 hash of authData||clientDataHash
	const verificationData = Buffer.concat([authData, clientDataHash])
	const nonce = createHash('sha256').update(verificationData).digest('base64')
	if (snr.nonce !== nonce) {
		throw new Error('Android SafetyNet: nonce mismatch')
	}

	// Success, attestation type basic
	return {
		type: 'basic' as const,
		path: decodeX5C(jws),
	}
}
