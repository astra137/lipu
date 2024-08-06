import type { MiddlewareHandler } from '$fresh/server.ts'

interface State {
	data: string
}

export const handler: MiddlewareHandler<State> = async (req, ctx) => {
	ctx.state.data = 'myData'
	const resp = await ctx.next()
	resp.headers.set('server', 'fresh server')
	return resp
}
