import {
	get,
	parseRequestOptionsFromJSON,
} from 'npm:@github/webauthn-json/browser-ponyfill'

import { Button } from '../components/Button.tsx'

type Props = {
	id?: string
}

export default function WebauthnGet(props: Props) {
	async function getCredential() {
		try {
			const url = props.id ? `/api/get?id=${props.id}` : '/api/get'
			const request = await fetch(url)
			const options = await request.json()
			const credential = await get(parseRequestOptionsFromJSON(options))
			const response = await fetch('/api/get', {
				method: 'POST',
				body: JSON.stringify(credential),
				headers: { 'content-type': 'application/json' },
			})
			const { location } = await response.json()
			if (location) window.location.pathname = location
		} catch (error) {
			console.warn(error)
		}
	}

	return (
		<Button onClick={getCredential}>
			Use passkey
		</Button>
	)
}
