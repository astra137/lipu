import type { Handlers, PageProps } from '$fresh/server.ts'
import { decodeBase64Url } from '$std/encoding/base64url.ts'
import { CodeJson } from '../../components/CodeJson.tsx'
import { type Attestation, getAttestation } from '../api/create.ts'

interface Data {
	challenge: string
	id: string
}

export const handler: Handlers<Data> = {
	async GET(_req, ctx) {
		const { challenge } = ctx.params
		// const credential = await getKey(ctx.params.id)
		// if (!credential) return ctx.renderNotFound()
		return ctx.render({ challenge, id: 'TODO' })
	},
}

export default function CredentialView(props: PageProps<Data>) {
	return (
		<div class='flex flex-col gap-4 px-4 py-4 overflow-x-hidden'>
			<div class='max-w-xl mx-auto'>
				<h1 class='text-3xl'>Assertion results</h1>
				<p>challenge={props.data.challenge}</p>
				<p>id={props.data.id}</p>
			</div>
		</div>
	)
}
