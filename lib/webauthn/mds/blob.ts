import { decodeBase64 } from '$std/encoding/base64.ts'
import { decode, verify } from 'https://deno.land/x/djwt@v3.0.2/mod.ts'
import { getCertStatus } from 'npm:easy-ocsp'
import * as pkijs from 'npm:pkijs'

import staticData from './blob.json' with { type: 'json' }

export const blob = staticData

const MDS3_URL = 'https://mds3.fidoalliance.org'

const GLOBALSIGN_R3_X509 = `
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
WD9f`

/** https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#metadata-blob-object-processing-rules */
async function fetchMetadataBlob() {
	const root = pkijs.Certificate.fromBER(decodeBase64(GLOBALSIGN_R3_X509))

	const response = await fetch(MDS3_URL)
	const jwt = await response.text()

	const { x5c, x5u } = decode(jwt)[0] as { x5c?: string[]; x5u?: string }
	if (x5u) throw new Error('x5u unimplemented')
	if (!x5c) throw new Error('invariant')

	const certs = x5c.map((x) => pkijs.Certificate.fromBER(decodeBase64(x)))
	const leaf = certs[0]

	// TODO
	// const name = new Name(leaf.subject).toJSON()
	// const match = name.find((x) => x['CN']?.includes(origin))
	// if (!match) throw new Error(`CN missing: ${origin}`)

	const chainEngine = new pkijs.CertificateChainValidationEngine({
		certs,
		trustedCerts: [root],
	})

	const chain = await chainEngine.verify()
	if (!chain.result) {
		throw new Error(chain.resultMessage, { cause: chain.error })
	}

	// SECURITY: Only the leaf certificate is checked for revocation.
	// As of July 2024, the token's trust path is 3 certs, including the root.
	// The root and intermediate certs don't provide URLs for CRL or OCSP.
	// I found a GlobalSign CRL, but the issuer only matches the leaf cert.
	// Does this imply that only the leaf cert might be revoked?
	// The following code assumes yes, and checks with OCSP.

	const ocspResult = await getCertStatus(leaf)
	if (ocspResult.status !== 'good') {
		throw new Error(`ocsp status: ${ocspResult.status}`)
	}

	const key = await leaf.getPublicKey()
	return await verify(jwt, key)
}

export async function loadMetadataBlob() {
	const cache = await caches.open('MDS3')
	const match = await cache.match(MDS3_URL)
	const previous = match ? await match.json() : null
	if (previous && new Date() < new Date(previous.nextUpdate)) return previous
	console.log('caching MDS3 blob')
	const payload = await fetchMetadataBlob()
	// if (previous && payload.no >= previous.no) throw new Error()
	await cache.put(MDS3_URL, Response.json(payload))
	return payload
}
