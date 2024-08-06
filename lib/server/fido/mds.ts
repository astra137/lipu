import fs from 'fs/promises'
import ow from 'ow'
import { verifyJWT } from './pki'

/**
 * Fetch the current MDS3 metadata blob.
 *
 * https://fidoalliance.org/metadata/
 */
export async function latest() {
	const res = await fetch('https://mds.fidoalliance.org')
	const jwt = await res.text()
	const blob = await verifyJWT(jwt, 'mds.fidoalliance.org')
	ow(blob, MDS3_OW)
	return blob
}

/**
 * TODO cache in Redis?
 */
export async function cached() {
	try {
		const json = await fs.readFile('mds.json', 'utf-8')
		const blob = JSON.parse(json)
		ow(blob, MDS3_OW)
		return blob
	} catch {
		const blob = await latest()
		const json = JSON.stringify(blob)
		await fs.writeFile('mds.json', json, 'utf-8')
		return blob
	}
}

//
//
//

//
// https://github.com/webauthn-open-source/fido2-lib/blob/master/lib/mds.js
//

const MDS3_OW = ow.object.exactShape({
	legalHeader: ow.string,

	no: ow.number,

	nextUpdate: ow.string,

	entries: ow.array.ofType(
		ow.object.exactShape({
			aaid: ow.optional.string,
			aaguid: ow.optional.string,
			attestationCertificateKeyIdentifiers: ow.optional.array.ofType(ow.string),

			timeOfLastStatusChange: ow.string,

			statusReports: ow.array.ofType(
				ow.object.exactShape({
					certificateNumber: ow.optional.string,
					certificationDescriptor: ow.optional.string,
					certificationPolicyVersion: ow.optional.string,
					certificationRequirementsVersion: ow.optional.string,
					effectiveDate: ow.string,
					status: ow.string.oneOf([
						'NOT_FIDO_CERTIFIED',
						'FIDO_CERTIFIED',
						'FIDO_CERTIFIED_L1',
						'FIDO_CERTIFIED_L2',
						'FIDO_CERTIFIED_L3',
					]),
					url: ow.optional.string,
				}),
			),

			metadataStatement: ow.object.exactShape({
				legalHeader: ow.string,

				aaid: ow.optional.string,
				aaguid: ow.optional.string,
				attestationCertificateKeyIdentifiers: ow.optional.array.ofType(
					ow.string,
				),

				description: ow.string,
				protocolFamily: ow.string.oneOf(['fido2', 'u2f', 'uaf']),
				authenticatorVersion: ow.number,
				schema: ow.number,
				icon: ow.string,

				alternativeDescriptions: ow.optional.object.valuesOfType(ow.string),

				isKeyRestricted: ow.optional.boolean,
				isFreshUserVerificationRequired: ow.optional.boolean,
				cryptoStrength: ow.optional.number,

				attestationTypes: ow.array.ofType(
					ow.string.oneOf(['basic_full', 'basic_surrogate', 'attca']),
				),

				attestationRootCertificates: ow.array.ofType(ow.string),

				// case 0x0001: return "ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW";
				// case 0x0002: return "ALG_SIGN_SECP256R1_ECDSA_SHA256_DER";
				// case 0x0003: return "ALG_SIGN_RSASSA_PSS_SHA256_RAW";
				// case 0x0004: return "ALG_SIGN_RSASSA_PSS_SHA256_DER";
				// case 0x0005: return "ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW";
				// case 0x0006: return "ALG_SIGN_SECP256K1_ECDSA_SHA256_DER";
				// case 0x0007: return "ALG_SIGN_SM2_SM3_RAW";
				// case 0x0008: return "ALG_SIGN_RSA_EMSA_PKCS1_SHA256_RAW";
				// case 0x0009: return "ALG_SIGN_RSA_EMSA_PKCS1_SHA256_DER";

				authenticationAlgorithms: ow.array.ofType(
					ow.string.oneOf([
						'ed25519_eddsa_sha512_raw',
						'rsa_emsa_pkcs1_sha256_raw',
						'secp256k1_ecdsa_sha256_raw',
						'secp256r1_ecdsa_sha256_der',
						'secp256r1_ecdsa_sha256_raw',
					]),
				),

				publicKeyAlgAndEncodings: ow.array.ofType(
					ow.string.oneOf([
						'cose',
						'ecc_x962_der',
						'ecc_x962_raw',
						'rsa_2048_der',
						'rsa_2048_raw',
					]),
				),

				keyProtection: ow.array.ofType(
					ow.string.oneOf([
						'software',
						'hardware',
						'tee',
						'secure_element',
						'remote_handle',
					]),
				),

				matcherProtection: ow.array.ofType(
					ow.string.oneOf([
						'software',
						// hardware is listed in webauthn-open-source/fido2-lib
						'on_chip',
						'tee',
					]),
				),

				attachmentHint: ow.optional.array.ofType(
					ow.string.oneOf([
						'bluetooth',
						'external',
						'internal',
						'nfc',
						'wired',
						'wireless',
					]),
				),

				tcDisplay: ow.array.ofType(ow.string.oneOf(['any'])),
				tcDisplayContentType: ow.optional.string.oneOf([
					'text/plain',
					'image/png',
				]),
				tcDisplayPNGCharacteristics: ow.optional.array.ofType(
					ow.object.exactShape({
						width: ow.number,
						height: ow.number,
						bitDepth: ow.number.oneOf([1, 16, 8]),
						colorType: ow.number.oneOf([3, 2, 6]),
						compression: ow.number.oneOf([0]),
						filter: ow.number.oneOf([0]),
						interlace: ow.number.oneOf([0]),
						plte: ow.optional.array.ofType(
							ow.object.exactShape({
								r: ow.number.greaterThanOrEqual(0).lessThanOrEqual(255),
								g: ow.number.greaterThanOrEqual(0).lessThanOrEqual(255),
								b: ow.number.greaterThanOrEqual(0).lessThanOrEqual(255),
							}),
						),
					}),
				),

				userVerificationDetails: ow.array.ofType(
					ow.array.ofType(
						ow.object.exactShape({
							userVerificationMethod: ow.string.oneOf([
								'none',
								'all',
								'eyeprint_internal',
								'faceprint_internal',
								'fingerprint_internal',
								'handprint_internal',
								'passcode_external',
								'passcode_internal',
								'pattern_internal',
								'presence_internal',
								'voiceprint_internal',
							]),
							caDesc: ow.optional.object.exactShape({
								base: ow.number.oneOf([10, 64]),
								minLength: ow.number,
								maxRetries: ow.number,
								blockSlowdown: ow.number,
							}),
							baDesc: ow.optional.object.exactShape({
								selfAttestedFRR: ow.number,
								selfAttestedFAR: ow.number,
								maxTemplates: ow.number,
								maxRetries: ow.number,
								blockSlowdown: ow.number,
							}),
							paDesc: ow.optional.object.exactShape({
								minComplexity: ow.number,
								maxRetries: ow.number,
								blockSlowdown: ow.number,
							}),
						}),
					),
				),

				upv: ow.any(
					ow.object.exactShape({
						major: ow.optional.number,
						minor: ow.optional.number,
					}),
					ow.array.ofType(
						ow.object.exactShape({
							major: ow.number,
							minor: ow.number,
						}),
					),
				),

				authenticatorGetInfo: ow.optional.object.exactShape({
					versions: ow.array.ofType(
						ow.string.oneOf(['FIDO_2_0', 'U2F_V2', 'FIDO_2_1_PRE', 'FIDO_2_1']),
					),
					extensions: ow.optional.array.ofType(
						ow.string.oneOf([
							'hmac-secret',
							'credProtect',
							'largeBlobKey',
							'credBlob',
							'minPinLength',
						]),
					),
					aaguid: ow.string,
					options: ow.object.exactShape({
						rk: ow.optional.boolean,
						uv: ow.optional.boolean,
						up: ow.optional.boolean,
						ep: ow.optional.boolean,
						alwaysUv: ow.optional.boolean,
						authnrCfg: ow.optional.boolean,
						bioEnroll: ow.optional.boolean,
						clientPin: ow.optional.boolean,
						credentialMgmtPreview: ow.optional.boolean,
						credMgmt: ow.optional.boolean,
						largeBlobs: ow.optional.boolean,
						makeCredUvNotRqd: ow.optional.boolean,
						pinUvAuthToken: ow.optional.boolean,
						plat: ow.optional.boolean,
						setMinPINLength: ow.optional.boolean,
						userVerificationMgmtPreview: ow.optional.boolean,
					}),
					maxMsgSize: ow.optional.number,
					pinUvAuthProtocols: ow.optional.array.ofType(ow.number.oneOf([1, 2])),
					maxCredentialCountInList: ow.optional.number,
					maxCredentialIdLength: ow.optional.number,
					transports: ow.optional.array.ofType(
						ow.string.oneOf(['nfc', 'usb', 'lightning', 'internal', 'ble']),
					),
					algorithms: ow.optional.array.ofType(
						ow.object.exactShape({
							type: ow.string.oneOf(['public-key']),
							alg: ow.number.oneOf([-7, -8, -257]),
						}),
					),
					minPINLength: ow.optional.number,
					firmwareVersion: ow.optional.number,
					certifications: ow.optional.object.exactShape({
						'FIPS-CMVP-2': ow.number.oneOf([2]),
						'FIPS-CMVP-2-PHY': ow.number.oneOf([3]),
					}),
					maxSerializedLargeBlobArray: ow.optional.number,
					maxCredBlobLength: ow.optional.number,
					maxRPIDsForSetMinPINLength: ow.optional.number,
					preferredPlatformUvAttempts: ow.optional.number,
					uvModality: ow.optional.number.oneOf([2]),
					remainingDiscoverableCredentials: ow.optional.number,
					forcePINChange: ow.optional.boolean,
				}),

				supportedExtensions: ow.optional.array.ofType(
					ow.object.exactShape({
						id: ow.string.oneOf([
							'fido.uaf.android.key_attestation',
							'hmac-secret',
						]),
						data: ow.optional.string,
						fail_if_unknown: ow.boolean,
					}),
				),
			}),
		}),
	),
})

/**
 * GlobalSign R3 root certificate, used to verify the MDS3 blob's x509 chain.
 *
 * https://valid.r3.roots.globalsign.com
 *
 * https://secure.globalsign.com/cacert/root-r3.crt
 *
 * @deprecated maybe in favor of tls.rootCertificates?
 */
const ROOT_GS_R3_CERT = `-----BEGIN CERTIFICATE-----
MIIDXzCCAkegAwIBAgILBAAAAAABIVhTCKIwDQYJKoZIhvcNAQELBQAwTDEgMB4G
A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjMxEzARBgNVBAoTCkdsb2JhbFNp
Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDkwMzE4MTAwMDAwWhcNMjkwMzE4
MTAwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMzETMBEG
A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAMwldpB5BngiFvXAg7aEyiie/QV2EcWtiHL8
RgJDx7KKnQRfJMsuS+FggkbhUqsMgUdwbN1k0ev1LKMPgj0MK66X17YUhhB5uzsT
gHeMCOFJ0mpiLx9e+pZo34knlTifBtc+ycsmWQ1z3rDI6SYOgxXG71uL0gRgykmm
KPZpO/bLyCiR5Z2KYVc3rHQU3HTgOu5yLy6c+9C7v/U9AOEGM+iCK65TpjoWc4zd
QQ4gOsC0p6Hpsk+QLjJg6VfLuQSSaGjlOCZgdbKfd/+RFO+uIEn8rUAVSNECMWEZ
XriX7613t2Saer9fwRPvm2L7DWzgVGkWqQPabumDk3F2xmmFghcCAwEAAaNCMEAw
DgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFI/wS3+o
LkUkrk1Q+mOai97i3Ru8MA0GCSqGSIb3DQEBCwUAA4IBAQBLQNvAUKr+yAzv95ZU
RUm7lgAJQayzE4aGKAczymvmdLm6AC2upArT9fHxD4q/c2dKg8dEe3jgr25sbwMp
jjM5RcOO5LlXbKr8EpbsU8Yt5CRsuZRj+9xTaGdWPoO4zzUhw8lo/s7awlOqzJCK
6fBdRoyV3XpYKBovHd7NADdBj+1EbddTKJd+82cEHhXXipa0095MJ6RMG3NzdvQX
mcIfeg7jLQitChws/zyrVQ4PkX4268NXSb7hLi18YIvDQVETI53O9zJrlAGomecs
Mx86OyXShkDOOyyGeMlhLxS67ttVb9+E7gUJTb0o2HLO02JQZR7rkpeDMdmztcpH
WD9f
-----END CERTIFICATE-----`
