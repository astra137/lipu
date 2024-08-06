import { toBytes } from 'fast-base64/js'
import { lap } from 'lib/web/vitreous'

export type PublicKeyCredentialDescriptorJson = {
	id: string
	transports?: AuthenticatorTransport[]
}

/** */
export type WebauthnType = 'webauthn.get' | 'webauthn.create'

interface BaseOptions {
	type: WebauthnType
	rpId?: string
	challenge: string
	timeout?: number
	extensions?: AuthenticationExtensionsClientInputs
	userVerification?: UserVerificationRequirement
}

/** */
export interface AssertionOptions extends BaseOptions {
	type: 'webauthn.get'
	allowCredentials?: PublicKeyCredentialDescriptorJson[]
}

/** */
export interface AttestationOptions extends BaseOptions {
	type: 'webauthn.create'
	rpName: 'astra137'
	user: { id: string; name: string; displayName: string }
	pubKeyCredParams: PublicKeyCredentialParameters[]
	excludeCredentials?: PublicKeyCredentialDescriptorJson[]
	authenticatorAttachment?: AuthenticatorAttachment
	residentKey?: ResidentKeyRequirement
	attestation?: AttestationConveyancePreference
}

/** */
function intoCreateOptions(
	json: AttestationOptions,
): PublicKeyCredentialCreationOptions {
	return {
		rp: {
			id: json.rpId,
			name: json.rpName,
		},
		user: {
			id: toBytes(json.user.id),
			name: json.user.name,
			displayName: json.user.displayName,
		},
		challenge: toBytes(json.challenge),
		pubKeyCredParams: json.pubKeyCredParams,
		excludeCredentials: json.excludeCredentials?.map((x) => ({
			type: 'public-key',
			id: toBytes(x.id),
			transports: x.transports,
		})),
		attestation: json.attestation,
		authenticatorSelection: {
			authenticatorAttachment: json.authenticatorAttachment,
			residentKey: json.residentKey,
			requireResidentKey: json.residentKey === 'required',
			userVerification: json.userVerification,
		},
		timeout: json.timeout,
		extensions: json.extensions,
	}
}

/** */
function intoRequestOptions(
	json: AssertionOptions,
): PublicKeyCredentialRequestOptions {
	return {
		rpId: json.rpId,
		challenge: toBytes(json.challenge),
		allowCredentials: json.allowCredentials?.map((x) => ({
			id: toBytes(x.id),
			type: 'public-key',
			transports: x.transports,
		})),
		timeout: json.timeout,
		userVerification: json.userVerification,
		extensions: json.extensions,
	}
}

/** */
export async function hasUVPA() {
	return PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
}

/** */
export async function optionsForGet() {
	const body = new URLSearchParams({}) // TODO ?
	const res = await fetch('/api/assertion/options', { method: 'POST', body })
	if (!res.ok) throw new Error(res.statusText)
	return intoRequestOptions(await res.json())
}

/** */
export async function webauthnGet(signal?: AbortSignal) {
	const publicKey = await optionsForGet()
	const credential = await navigator.credentials.get({ publicKey, signal })
	if (!(credential instanceof PublicKeyCredential)) {
		throw new Error('PublicKeyCredential')
	}
	if (!(credential.response instanceof AuthenticatorAssertionResponse)) {
		throw new Error('AuthenticatorAssertionResponse')
	}
	const body = lap(
		credential.rawId,
		credential.response.clientDataJSON,
		credential.response.authenticatorData,
		credential.response.signature,
		credential.response.userHandle ?? new Uint8Array(0),
		new TextEncoder().encode(
			JSON.stringify({
				...credential.getClientExtensionResults(),
			}),
		),
	)

	const res = await fetch('/api/assertion/result', { method: 'POST', body })
	return res.json()
}

/** */
export async function optionsForCreate() {
	const body = new URLSearchParams({})
	const res = await fetch('/api/attestation/options', { method: 'POST', body })
	if (!res.ok) throw new Error(res.statusText)
	return intoCreateOptions(await res.json())
}

/** */
export async function webauthnCreate(signal?: AbortSignal) {
	const publicKey = await optionsForCreate()
	const credential = await navigator.credentials.create({ publicKey, signal })
	if (!(credential instanceof PublicKeyCredential)) {
		throw new Error('PublicKeyCredential')
	}
	if (!(credential.response instanceof AuthenticatorAttestationResponse)) {
		throw new Error('AuthenticatorAttestationResponse')
	}
	const body = lap(
		credential.rawId,
		credential.response.clientDataJSON,
		credential.response.attestationObject,
		new TextEncoder().encode(
			JSON.stringify(credential.getClientExtensionResults()),
		),
	)

	const res = await fetch('/api/attestation/result', { method: 'POST', body })
	return res.json()
}
