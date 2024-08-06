import type { Handlers, PageProps } from '$fresh/server.ts'
import { decodeBase64Url } from '$std/encoding/base64url.ts'
import { CodeJson } from '../../components/CodeJson.tsx'
import { type Attestation, getAttestation } from '../api/create.ts'
import {
	inspectAttestationObject,
	inspectAuthData,
} from '../../lib/webauthn/mod.ts'
import { blob } from '../../lib/webauthn/mds/blob.ts'
import { bytesToUuid } from '$std/uuid/_common.ts'
import WebauthnGet from '../../islands/WebauthnGet.tsx'

interface Data {
	description: string
	credential: Attestation
	clientDataJSON: unknown
	attestationObject: unknown
	authData: unknown
	metadata: unknown
}

export const handler: Handlers<Data> = {
	async GET(_req, ctx) {
		const credential = await getAttestation(ctx.params.id)

		if (!credential) return ctx.renderNotFound()

		const clientDataJSON = JSON.parse(
			new TextDecoder().decode(
				decodeBase64Url(credential.response.clientDataJSON),
			),
		)

		const attestationObject = inspectAttestationObject(
			decodeBase64Url(credential.response.attestationObject),
		)

		const authData = inspectAuthData(attestationObject.authData)

		let metadata = null

		if (authData.attestedCredentialData) {
			const aaguid = bytesToUuid(authData.attestedCredentialData.aaguid)
			metadata = blob.entries.find((x) => x.aaguid === aaguid)
		}

		const description = metadata?.metadataStatement.description ??
			'Unknown authenticator'

		return ctx.render({
			description,
			credential,
			clientDataJSON,
			attestationObject,
			authData,
			metadata,
		})
	},
}

export default function CredentialView(props: PageProps<Data>) {
	return (
		<div class='flex flex-col gap-4 px-4 py-4 overflow-x-hidden'>
			<div class='max-w-xl mx-auto'>
				<h1 class='text-3xl'>{props.data.description}</h1>
				<WebauthnGet id={props.data.credential.id} />
				<a href='/'>Start over</a>
			</div>

			<CodeJson
				summary='credential'
				data={props.data.credential}
			/>
			<CodeJson
				summary='credential.response.clientDataJSON'
				data={props.data.clientDataJSON}
			/>
			<CodeJson
				summary='credential.response.attestationObject'
				data={props.data.attestationObject}
			/>
			<CodeJson
				summary='credential.response.attestationObject.authData'
				data={props.data.authData}
			/>
			<CodeJson
				summary='metadata search result'
				data={props.data.metadata}
			/>
		</div>
	)
}
