interface OIDC {
	issuer: string
	jwks_uri: string
	scopes_supported: string[]
	authorization_endpoint: string
	revocation_endpoint: string
}

type Domain = 'accounts.google.com'

export async function getOIDC(domain: Domain): Promise<OIDC> {
	const wellKnown = '/.well-known/openid-configuration'
	const url = new URL(wellKnown, `https://${domain}`)
	const resp = await fetch(url.href)
	if (!resp.ok) throw new Error(resp.statusText)
	return await resp.json()
}

// https://developers.google.com/identity/protocols/oauth2/openid-connect

export type Prompt = 'none' | 'consent' | 'select_account'

export async function identWithGoogle(
	state: string,
	nonce: string,
	hint?: string,
	prompt?: Prompt,
) {
	const oidc = await getOIDC('accounts.google.com')
	const url = new URL(oidc.authorization_endpoint)
	url.searchParams.set('client_id', process.env.GOOGLE_CLIENT_ID!)
	url.searchParams.set('response_type', 'id_token')
	url.searchParams.set('scope', 'openid email')
	url.searchParams.set('redirect_uri', new URL('/cb', origin).href)
	url.searchParams.set('state', state)
	url.searchParams.set('nonce', nonce)
	if (hint) url.searchParams.set('login_hint', hint)
	if (prompt) url.searchParams.set('prompt', prompt)
	return url
}

export interface CallbackData {
	state: string
	prompt: Prompt
	authuser: string
	id_token: string
}

export function parseHash(location: Location) {
	if (location.hash) {
		const params = new URLSearchParams(location.hash.slice(1))
		const state = params.get('state')
		const prompt = params.get('prompt') as Prompt | null
		const authuser = params.get('authuser')
		const id_token = params.get('id_token')

		if (!state) throw new Error('state')
		if (!prompt) throw new Error('prompt')
		if (!authuser) throw new Error('authuser')
		if (!id_token) throw new Error('id_token')

		return <CallbackData> {
			state,
			prompt,
			authuser,
			id_token,
		}
	}
}
