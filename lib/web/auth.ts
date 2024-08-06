import { CallbackData, identWithGoogle } from './oidc'
import { lap } from './vitreous'

export function getRandomBase64url(byteLength: number) {
	return lap(crypto.getRandomValues(new Uint8Array(byteLength)))
}

/** */
export async function oauthPopup(signal?: AbortSignal) {
	const state = getRandomBase64url(12)
	const nonce = getRandomBase64url(24)

	const w = window.open('/id', 'ident', '')
	if (!w) throw new Error()
	w.sessionStorage.setItem('state', state)
	w.sessionStorage.setItem('nonce', nonce)

	let interval: any

	const idResult = await new Promise<CallbackData | null>((resolve, reject) => {
		signal?.addEventListener('abort', (e) => reject(e))
		w.onclose = (e) => reject(e)
		interval = setInterval(() => {
			if (w.closed) reject(new Error('closed'))
		}, 731)

		addEventListener('message', async (e) => {
			if (e.source !== w) return
			if (e.origin !== origin) return
			const { type, ...data } = e.data
			switch (type) {
				case 'id:ready': {
					console.log('ident ready')
					return
				}
				case 'id:webauthn': {
					return resolve(null)
				}
				case `callback`: {
					if (data.state !== state) return reject()
					return resolve(data)
				}
			}
		})
	}).finally(() => {
		w.close()
		clearInterval(interval)
	})

	console.debug('done', idResult)
}

//
//
//

/** */
export async function googlePopup(opt: {
	hint?: string
	signal?: AbortSignal
}) {
	const state = getRandomBase64url(12)
	const nonce = getRandomBase64url(24)
	const url = await identWithGoogle(state, nonce, opt.hint)

	const w = window.open(url, 'ident', '')
	if (!w) throw new Error()

	let interval: any

	return await new Promise<CallbackData>((resolve, reject) => {
		opt.signal?.addEventListener('abort', (e) => reject(e))

		let lastLoop = false
		interval = setInterval(() => {
			if (w.closed) {
				if (lastLoop) {
					reject(new Error('closed'))
				} else {
					lastLoop = true
				}
			}
		}, 500)

		addEventListener('message', async (e) => {
			if (e.source !== w) return
			if (e.origin !== origin) return
			if (e.data.state === state) {
				resolve(e.data)
			}
		})
	}).finally(() => {
		w.close()
		clearInterval(interval)
	})
}
