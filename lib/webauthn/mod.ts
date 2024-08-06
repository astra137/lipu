import { decodeBase64Url } from '$std/encoding/base64url.ts'
import * as bytes from '$std/bytes/mod.ts'
import * as AuthData from './authdata.ts'
import type { AttestationObject, CollectedClientData } from './types.d.ts'
import type { CredentialCreationOptionsJSON } from 'npm:@github/webauthn-json'
import type { PublicKeyCredentialWithAttestationJSON } from 'npm:@github/webauthn-json'
import { Decoder } from 'https://deno.land/x/cbor@v1.5.9/decode.js'

export function inspectAttestationObject(data: Uint8Array) {
	const decoder = new Decoder({ useRecords: true })
	const attObj = decoder.decode(data)
	return {
		fmt: attObj.get('fmt'),
		attStmt: attObj.get('attStmt'),
		authData: attObj.get('authData'),
	}
}

export function inspectAuthData(data: Uint8Array) {
	const rpIdHash = AuthData.rpIdHash(data)
	const flags = AuthData.flags(data)
	const signCount = AuthData.signCount(data)
	const extensions = AuthData.extensions(data)
	const attestedCredentialData = flags.at
		? {
			aaguid: AuthData.aaguid(data),
			credentialId: AuthData.credentialId(data),
			credentialPublicKey: AuthData.credentialPublicKey(data),
		}
		: undefined
	return {
		rpIdHash,
		flags,
		signCount,
		extensions,
		attestedCredentialData,
	}
}

// import { verifyPacked } from './packed'
// import { verifyAndroidSafetyNet } from './android-safetynet'
// import { verifyU2F } from './fido-u2f'

// export function verifyAttestation(
// 	fmt: string,
// 	attStmt: Uint8Array,
// 	authData: Uint8Array,
// 	hash: Uint8Array,
// ) {
// 	throw new Error('unimplemented')
// }

// async function sha256(x: BufferSource) {
// 	return new Uint8Array(await crypto.subtle.digest('SHA-256', x))
// }

// export type RegistrationContext = {
// 	origin: string
// 	userVerificationRequired: boolean
// 	options: CredentialCreationOptionsJSON['publicKey']
// 	credential: PublicKeyCredentialWithAttestationJSON
// }

// /** https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential */
// export async function registrationCeremony(ctx: RegistrationContext) {
// 	const response = ctx.credential.response
// 	const clientDataJSON = decodeBase64Url(response.clientDataJSON)
// 	const attestationObject = decodeBase64Url(response.attestationObject)

// 	const clientExtensionResults = ctx.credential.clientExtensionResults

// 	const JSONtext = new TextDecoder().decode(clientDataJSON)

// 	const C = JSON.parse(JSONtext) as CollectedClientData

// 	if (C.type !== 'webauthn.create') {
// 		throw new Error(`invalid type: ${C.type}`)
// 	}

// 	if (C.challenge !== ctx.options.challenge) {
// 		throw new Error(`invalid challenge: ${C.challenge}`)
// 	}

// 	if (C.origin !== ctx.origin) {
// 		throw new Error(`invalid origin: ${C.origin}`)
// 	}

// 	if (C.tokenBinding?.status) {
// 		throw new Error('tokenBinding unimplemented')
// 	}

// 	const decoder = new Decoder({ useRecords: true })
// 	const attObj: AttestationObject = decoder.decode(attestationObject)
// 	const { fmt, attStmt, authData } = attObj

// 	const rpIdHash = await sha256(new TextEncoder().encode(options.rp.id))
// 	if (!bytes.equals(AuthData.rpIdHash(authData), rpIdHash)) {
// 		throw new Error('invalid rpIdHash')
// 	}

// 	if (!AuthData.flags(authData).up) {
// 		throw new Error('User Present unset')
// 	}

// 	if (ctx.userVerificationRequired && !AuthData.flags(authData).uv) {
// 		throw new Error('User Verified unset')
// 	}

// 	const alg = AuthData.credentialAlg(authData)
// 	if (ctx.options.pubKeyCredParams.map((x) => x.alg).indexOf(alg) < 0) {
// 		throw new Error(`invalid alg: ${alg}`)
// 	}

// 	const extensions = AuthData.extensions(authData)

// 	switch (fmt) {
// 		case 'none':
// 		case 'packed':
// 		case 'tpm':
// 		case 'android-key':
// 		case 'android-safetynet':
// 		case 'fido-u2f':
// 		case 'apple': {
// 			break
// 		}
// 		default: {
// 			throw new Error(`unsupported fmt: ${fmt}`)
// 		}
// 	}

// 	const hash = await sha256(clientDataJSON)
// 	const trustPath = verifyAttestation(fmt, attStmt, authData, hash)

// 	// Obtain trust anchors

// 	// Verify attestation trustworthiness

// 	// Check that the credentialId is not yet registered

// 	// Register the new credential public key, signature counter, transport hints
// }
