import type { Handlers, PageProps } from '$fresh/server.ts'
import { getCookies, setCookie } from '$std/http/cookie.ts'
import { createToken, verifyToken } from '../lib/providers/tokens.ts'
import { CodeJson } from '../components/CodeJson.tsx'

interface Data {
	csrf: string
}

export const handler: Handlers<Data> = {
	GET(req, ctx) {
		const url = new URL(req.url)
		const csrfCookie = url.hostname === 'localhost' ? 'csrf' : '__Host-csrf'
		const csrf = Math.random().toString(36).slice(2)
		const headers = new Headers()
		setCookie(headers, {
			secure: true,
			httpOnly: true,
			sameSite: 'Strict',
			path: '/',
			name: csrfCookie,
			value: csrf,
		})
		return ctx.render({ csrf }, { headers })
	},

	async POST(req, _ctx) {
		const url = new URL(req.url)
		const csrfCookie = url.hostname === 'localhost' ? 'csrf' : '__Host-csrf'
		const cookies = getCookies(req.headers)
		const data = await req.formData()
		if (cookies[csrfCookie] !== data.get('csrf')) {
			return new Response(null, { status: 401 })
		}
		if (data.get('secret') !== Deno.env.get('TOKEN_SECRET')) {
			return new Response(null, { status: 401 })
		}
		// TODO
		const headers = new Headers()
		headers.set('location', url.pathname)
		return new Response(null, { status: 303, headers })
	},
}

export default function Sudo(props: PageProps<Data>) {
	return (
		<div class='px-4 py-4 max-w-prose mx-auto flex flex-col'>
			<form method='post' class='flex flex-col gap-4'>
				<input
					type='password'
					name='secret'
					placeholder='secret'
					class='px-2 py-2 bg-transparent rounded border border-gray-600 hover:border-green-600 hover:text-green-600 cursor-pointer'
				/>
				<input
					type='url'
					name='me'
					placeholder='me'
					class='px-2 py-2 bg-transparent rounded border border-gray-600 hover:border-green-600 hover:text-green-600 cursor-pointer'
				/>
				<input
					type='text'
					name='webauthn'
					placeholder='webauthn'
					class='px-2 py-2 bg-transparent rounded border border-gray-600 hover:border-green-600 hover:text-green-600 cursor-pointer'
				/>
				<input type='hidden' name='csrf' value={props.data.csrf} />
				<button
					type='submit'
					class='px-2 py-2 bg-transparent font-semibold rounded border border-gray-600 hover:border-green-600 hover:text-green-600 cursor-pointer'
				>
					set admin passkey
				</button>
			</form>
		</div>
	)
}
