import { decode } from 'https://deno.land/x/cbor_redux@1.0.0/mod.ts'
import { verifyPacked } from './packed'
import { verifyAndroidSafetyNet } from './android-safetynet'
import { verifyU2F } from './fido-u2f'

/** */
export function verifyAttestation(
	attestationObject: Uint8Array,
	clientDataHash: Uint8Array,
) {
	const fmt = decode(attestationObject).fmt

	switch (fmt) {
		case 'none': {
			return { type: 'none', path: [] }
		}

		case 'packed': {
			return verifyPacked(attestationObject, clientDataHash)
		}

		case 'tpm': {
			throw new Error('tpm not implemented')
		}

		case 'android-key': {
			throw new Error('android-key not implemented')
		}

		case 'android-safetynet': {
			return verifyAndroidSafetyNet(attestationObject, clientDataHash)
		}

		case 'fido-u2f': {
			return verifyU2F(attestationObject, clientDataHash)
		}

		default: {
			throw new Error(`unsupported fmt=${fmt}`)
		}
	}
}
