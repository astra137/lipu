import {
	create,
	parseCreationOptionsFromJSON,
} from 'npm:@github/webauthn-json/browser-ponyfill'
import { Button } from '../components/Button.tsx'

export default function WebauthnCreate() {
	async function createCredential() {
		try {
			const request = await fetch('/api/create')
			const options = await request.json()
			const credential = await create(parseCreationOptionsFromJSON(options))
			const response = await fetch('/api/create', {
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
		<Button onClick={createCredential}>
			Register new passkey
		</Button>
	)
}
