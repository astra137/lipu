export interface CollectedClientData {
	type: 'webauthn.get' | 'webauthn.create'
	challenge: string
	origin: string
	/** https://www.w3.org/TR/webauthn-1/#dom-collectedclientdata-tokenbinding */
	tokenBinding?: {
		status: 'supported' | 'present'
		id?: string
	}
	/** Chrome Windows 10 added this */
	crossOrigin?: boolean
	/** Observed to be added by Chrome Android 11 Pixel 5 */
	androidPackageName?: string
}

export interface AuthenticatorData {
	rpIdHash: ArrayBuffer
	flagsValue: number
	flags: {
		up: boolean
		uv: boolean
		at: boolean
		ed: boolean
	}
	signCount: number
	attestedCredentialData?: {
		aaguid: ArrayBuffer
		credentialId: ArrayBuffer
		credentialPublicKey: Map<unknown, unknown>
	}
	extensions?: Record<string, unknown>
}

export type AttestationObject = {
	fmt: string
	authData: Uint8Array
	attStmt: Uint8Array
}
