import adapter from 'webrtc-adapter'
import { lap } from './vitreous'

/** */
async function hmac(secret: string, message: string) {
	const alg = { name: 'HMAC', hash: 'SHA-256' }
	const raw = new TextEncoder().encode(secret)
	const data = new TextEncoder().encode(message)
	const ck = await crypto.subtle.importKey('raw', raw, alg, false, ['sign'])
	const sig = await crypto.subtle.sign('HMAC', ck, data)
	return lap(new Uint8Array(sig))
}

/** */
function sendFn(url: string, signal: AbortSignal) {
	return async (type: string, data: unknown) => {
		const res = await fetch(url, {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ type, data }),
			signal,
		})
		if (!res.ok) throw new Error(res.statusText)
		await res.text()
	}
}

/** */
async function nextMessage<T>(channel: RTCDataChannel, signal: AbortSignal) {
	const tmpAC = new AbortController()
	const data = await new Promise<string | void>((resolve, reject) => {
		const none = () => resolve()
		const some = (e: MessageEvent<string>) => resolve(e.data)
		const opt = { once: true, signal: tmpAC.signal }
		signal.addEventListener('abort', reject, opt)
		channel.addEventListener('error', reject, opt)
		channel.addEventListener('close', none, opt)
		channel.addEventListener('message', some, opt)
	}).finally(() => tmpAC.abort())
	if (data !== undefined) return JSON.parse(data) as Tuple<T>
}

/** */
const RTC_CONFIG: RTCConfiguration = {
	iceServers: [
		// { urls: 'stun:stun.l.google.com:19302' },
		// { urls: 'stun:stun.stunprotocol.org' },
		// {
		// 	urls: 'turn:numb.viagenie.ca',
		// 	credential: 'muazkh',
		// 	username: 'webrtc@live.com',
		// },
	],
}

type Tuple<T> = { [K in keyof T]: [type: K, data: T[K]] }[keyof T]

interface InnerChannel<T extends Record<string, unknown>> {
	send(type: string, data: unknown): Promise<void>
	receive<K extends keyof T>(type: K): Promise<T[K]>
}

/** */
export async function bindingChannel<T extends Record<string, unknown>>(
	key: string,
	abortSignal: AbortSignal,
	fn: (channel: InnerChannel<T>) => Promise<void>,
) {
	const id = toUrl(toBase64(crypto.getRandomValues(new Uint8Array(6))))
	const url = `http://localhost:8080/signals/${key}?id=${id}`

	const ac = new AbortController()
	const pc = new RTCPeerConnection(RTC_CONFIG)
	const sse = new EventSource(url)
	const signal = sendFn(url, abortSignal)

	ac.signal.addEventListener('abort', () => pc.close())
	ac.signal.addEventListener('abort', () => sse.close())
	abortSignal.addEventListener('abort', () => ac.abort())
	sse.addEventListener('error', () => ac.abort())

	//
	//
	//

	await new Promise<void>((resolve, reject) => {
		sse.addEventListener('open', () => resolve())
		sse.addEventListener('error', reject)
		ac.signal.addEventListener('abort', reject)
	})

	const [, polite] = await Promise.all([
		//
		signal('syn', undefined),

		//
		new Promise<boolean>((resolve, reject) => {
			const opt = { signal: ac.signal }
			sse.addEventListener('error', reject)
			ac.signal.addEventListener('abort', reject)

			sse.addEventListener(
				'syn',
				() => {
					signal('ack', undefined)
					resolve(true)
				},
				opt,
			)

			sse.addEventListener(
				'ack',
				() => {
					resolve(false)
				},
				opt,
			)
		}),
	])

	//
	//
	//

	let makingOffer = false
	let ignoreOffer = false
	let isSettingRemoteAnswerPending = false

	const descriptionOther = async (description: RTCSessionDescriptionInit) => {
		const readyForOffer = !makingOffer &&
			(pc.signalingState === 'stable' || isSettingRemoteAnswerPending)
		const offerCollision = description.type === 'offer' && !readyForOffer
		ignoreOffer = !polite && offerCollision
		if (ignoreOffer) return
		isSettingRemoteAnswerPending = description.type === 'answer'
		await pc.setRemoteDescription(description) // SRD rolls back as needed
		isSettingRemoteAnswerPending = false
		if (description.type === 'offer') {
			await pc.setLocalDescription()
			await signal('message', { description: pc.localDescription })
		}
	}

	const candidateOther = async (candidate: RTCIceCandidateInit) => {
		if (candidate) {
			try {
				await pc.addIceCandidate(candidate)
			} catch (err) {
				if (!ignoreOffer) throw err
			}
		} else {
			console.debug('candidate', candidate)
		}
	}

	sse.addEventListener('message', async ({ data }) => {
		const { candidate, description } = JSON.parse(data)
		if (description) {
			await descriptionOther(description)
		} else if (candidate) {
			await candidateOther(candidate)
		} else if (candidate === null) {
			// This seems to always be sent last
		} else {
			console.warn('unknown message', data)
		}
	})

	//
	//
	//

	pc.addEventListener('icecandidate', ({ candidate }) => {
		return signal('message', { candidate })
	})

	pc.addEventListener('icecandidateerror', (event) => {
		console.error('icecandidateerror', event)
	})

	pc.addEventListener('negotiationneeded', async () => {
		console.debug('negotiationneeded')
		try {
			makingOffer = true
			await pc.setLocalDescription()
			await signal('message', { description: pc.localDescription })
		} catch (err) {
			console.error(err)
		} finally {
			makingOffer = false
		}
	})

	pc.addEventListener('iceconnectionstatechange', () => {
		console.debug('iceConnectionState', pc.iceConnectionState)
		switch (pc.iceConnectionState) {
			case 'failed':
				//  re-negotiate from the beginning
				break
			case 'closed':
				ac.abort()
				break
			default:
		}
	})

	pc.addEventListener('icegatheringstatechange', () => {
		console.debug('iceGatheringState', pc.iceGatheringState)
	})

	pc.addEventListener('signalingstatechange', () => {
		console.debug('signalingState', pc.signalingState)
	})

	pc.addEventListener('connectionstatechange', () => {
		console.debug('connectionState', pc.connectionState)
	})

	//
	//
	//

	const outgoing = await new Promise<RTCDataChannel>((resolve, reject) => {
		const channel = pc.createDataChannel('streamingchan')
		const opt = { once: true, signal: ac.signal }
		ac.signal.addEventListener('abort', reject, opt)
		channel.addEventListener('open', () => resolve(channel), opt)
		channel.addEventListener('error', reject, opt)
		channel.addEventListener('close', reject, opt)
	})

	const incoming = await new Promise<RTCDataChannel>((resolve, reject) => {
		const opt = { once: true, signal: ac.signal }
		ac.signal.addEventListener('abort', reject, opt)
		pc.addEventListener(
			'datachannel',
			({ channel }) => {
				channel.addEventListener('open', () => resolve(channel), opt)
				channel.addEventListener('error', reject, opt)
				channel.addEventListener('close', reject, opt)
			},
			opt,
		)
	})

	//
	//
	//

	await fn({
		async send(...[type, data]) {
			outgoing.send(JSON.stringify([type, data]))
		},
		async receive<K extends keyof T>(expected: K) {
			const value = await nextMessage<T>(incoming, ac.signal)
			if (value === undefined) throw new Error(`value === undefined`)
			const [type, data] = value
			if (type !== expected) throw new Error(`${type} !== ${expected}`)
			return data as T[K]
		},
	})

	// TODO
	// Is this really a good way to do this?
	ac.abort()
}
