import crypto from 'crypto'
import { rootCertificates } from 'tls'
import { Name, X509Certificate, X509ChainBuilder } from '@peculiar/x509'
import {
	compactVerify,
	decodeProtectedHeader,
	JWSHeaderParameters,
	jwtVerify,
} from 'jose'

export async function verifyJWT(jwt: string, origin: string) {
	const { payload, protectedHeader } = await jwtVerify(jwt, GetKeyFromX509)
	const leaf = new X509Certificate(protectedHeader.x5c![0])
	const name = new Name(leaf.subject).toJSON()
	const match = name.find((x) => x['CN']?.includes(origin))
	if (!match) throw new Error(`CN missing: ${origin}`)
	return payload
}

export async function verifyCompactJWS(jws: string, origin: string) {
	const { payload, protectedHeader } = await compactVerify(jws, GetKeyFromX509)
	const leaf = new X509Certificate(protectedHeader.x5c![0])
	const name = new Name(leaf.subject).toJSON()
	const match = name.find((x) => x['CN']?.includes(origin))
	if (!match) throw new Error(`CN missing: ${origin}`)
	return payload
}

export function decodeX5C(jws: string) {
	const header = decodeProtectedHeader(jws)
	const x5c = header.x5c!.map((x) => new X509Certificate(x))
	return x5c
}

//
//
//

/** Verify X509 chain, then extract the leaf certificate public key. */
async function GetKeyFromX509(header: JWSHeaderParameters) {
	const x5c = header.x5c!.map((x) => new X509Certificate(x))
	const leaf = await verifyChain(x5c)
	return crypto.createPublicKey(leaf.toString())
}

/**
 * TODO switch back to manual certs? Only one root for SafetyNet and MDS...
 *
 * SAFETY NOTE a serious lack of CRL checking. */
const ROOT_CERTS = rootCertificates.map((x) => new X509Certificate(x))

/** I cannot believe, that this isn't a runtime primative. D: */
async function verifyChain(x5c: X509Certificate[]) {
	const [leaf, ...branches] = x5c

	const chain = new X509ChainBuilder({
		certificates: [...branches, ...ROOT_CERTS],
	})

	const chainPath = await chain.build(leaf)

	const chainRoot = chainPath.find((x) => ROOT_CERTS.find((ca) => x.equal(ca)))
	if (!chainRoot) throw new Error('chain missing root cert')

	for (let i = 0; i < chainPath.length - 1; i++) {
		const a = chainPath[i]
		const b = chainPath[i + 1]
		if (!(await a.verify({ publicKey: b.publicKey }))) {
			throw new Error('cert chain verify failed')
		}
	}

	return leaf
}
