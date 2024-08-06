import { useEffect, useRef, useState } from 'react'
import useSWR, { useSWRConfig } from 'swr'
import { webauthnGet } from 'lib/web/webauthn'
import { googlePopup } from 'lib/web/auth'
import { bobaCreate, bobaDelete, bobaSession, bobaToken } from 'lib/web/boba'

class ApiError extends Error {
	status?: number
	statusText?: string
}

/** */
async function fetcher<T>(url: string, sid: string): Promise<T> {
	await new Promise((r) => setTimeout(r, 1000))
	const token = await bobaToken(sid)
	const res = await fetch(url, { headers: { authorization: `BOBA ${token}` } })
	if (!res.ok) {
		const err = new ApiError(`API status: ${res.statusText}`)
		err.status = res.status
		err.statusText = res.statusText
		throw err
	}
	return await res.json()
}

/** */
export function useApiUser() {
	const sess = useSWR<string | null>('sid', () => bobaSession())
	const user = useSWR<UserInfo>(sess.data ? ['/api/user', sess.data] : null, {
		fetcher,
	})

	const dismount = useRef<AbortSignal>()
	useEffect(() => {
		const ac = new AbortController()
		dismount.current = ac.signal
		return () => ac.abort()
	}, [])

	const { mutate } = useSWRConfig()
	const [mutating, setMutating] = useState(false)

	useEffect(() => {
		if (user.error instanceof ApiError) {
			if (user.error.status === 401) {
				console.warn('signing user out due to bad token')
				signOut()
			}
		}
	}, [user.error])

	const signIn = async (email?: string) => {
		try {
			setMutating(true)
			if (user.data) return
			const { token } = await webauthnGet(email, dismount.current!)
			const sid = await bobaCreate(`webauthn.get ${token}`)
			mutate('sid', sid)
		} catch (err) {
			// TODO: toast? state? dialog?
			console.error(err)
		} finally {
			setMutating(false)
		}
	}

	const signOut = async () => {
		try {
			setMutating(true)
			if (!sess.data) return
			mutate('sid', null, false)
			await bobaDelete(sess.data)
		} catch (err) {
			// TODO: toast? state? dialog?
			console.error(err)
		} finally {
			setMutating(false)
		}
	}

	return {
		loading: sess.isValidating || user.isValidating,
		error: sess.error ?? user.error,
		data: sess.data === null ? null : user.data,
		mutating,
		signIn,
		signOut,
	}
}
