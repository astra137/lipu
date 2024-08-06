import { assertEquals } from '$std/assert/mod.ts'
import { registrationCeremony, type RegistrationContext } from './mod.ts'

Deno.test('registration with Windows Hello', async () => {
	const ctx: RegistrationContext = {
		origin: 'http://localhost:8000',
		userVerificationRequired: false,
		options: {
			challenge: '_kxRni2GM4eEna7Kzl41PJ-YtHfd9gVKdxD0GOPSDZc',
			rp: {
				id: 'localhost',
				name: 'Webauthn Inspector',
			},
			user: {
				id: '_kxRni2GM4eEna7Kzl41PJ-YtHfd9gVKdxD0GOPSDZc',
				name: 'test@example.com',
				displayName: 'Test User',
			},
			pubKeyCredParams: [
				{ type: 'public-key', alg: -7 },
				{ type: 'public-key', alg: -257 },
			],
			authenticatorSelection: {
				residentKey: 'required',
				userVerification: 'preferred',
			},
			attestation: 'direct',
			timeout: 120_000,
			extensions: {
				credProps: true,
			},
		},
		credential: {
			type: 'public-key',
			id: 'mFXUn1ps4eyUn3SzYIRM0RyaPv4vSe1LMUoxZ1bqE0I',
			rawId: 'mFXUn1ps4eyUn3SzYIRM0RyaPv4vSe1LMUoxZ1bqE0I',
			authenticatorAttachment: 'platform',
			response: {
				clientDataJSON:
					'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiX2t4Um5pMkdNNGVFbmE3S3psNDFQSi1ZdEhmZDlnVktkeEQwR09QU0RaYyIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0',
				attestationObject:
					'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAAiYcFjK3EuBtuEw3lDcvpYAIJhV1J9abOHslJ90s2CETNEcmj7-L0ntSzFKMWdW6hNCpQECAyYgASFYILpJaiVv0E-Agt1yDvjnhw6m61Ruuo7zFpwPGmW2N5CyIlgg4AUY4z4Vn1bgAqCu0_twF6NqDSzo8XH3UMZXO-DgPtc',
				transports: [
					'internal',
				],
			},
			clientExtensionResults: {
				credProps: {
					rk: true,
				},
			},
		},
	}

	const ceremony = registrationCeremony(ctx)

	let current = 0
	try {
		for await (const step of ceremony) {
			current = step
		}
	} catch (cause) {
		throw new Error(`Registration failed on step ${current}`, { cause })
	}
})
