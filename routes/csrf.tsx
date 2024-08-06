import type { Handlers, PageProps } from '$fresh/server.ts'
import { getCookies, setCookie } from '$std/http/cookie.ts'
import { Button } from '../components/Button.tsx'

interface Data {
	csrf: string
}

export const handler: Handlers<Data> = {
	GET(req, ctx) {
		const url = new URL(req.url)
		const csrfCookie = url.hostname === 'localhost' ? 'csrf' : '__Host-csrf'
		// const cookies = getCookies(req.headers)
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
			return new Response(null, { status: 400 })
		}
		const headers = new Headers()
		headers.set('location', url.pathname)
		return new Response(null, {
			status: 303, // "See Other"
			headers,
		})
	},
}

export default function Home({ data }: PageProps<Data>) {
	return (
		<div class='px-4 py-4'>
			<form method='post'>
				<input type='hidden' name='csrf' value={data.csrf} />
				<Button type='submit'>Submit</Button>
			</form>
		</div>
	)
}
