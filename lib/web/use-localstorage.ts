import { useEffect, useRef, useState } from 'react'

type UseLocalStorage<T> = [
	value: T | null,
	setValue: (value: T | null) => void,
]

/** */
export function useLocalStorage<T extends string>(
	key: string,
	initial: T | null = null,
): UseLocalStorage<T> {
	const [value, __setValue] = useState<T | null>(null)

	const mounted = useRef<boolean>(false)
	const channel = useRef<BroadcastChannel>()
	const debounce = useRef<number>()

	useEffect(() => {
		const fn = () => {
			if (debounce.current) cancelAnimationFrame(debounce.current)
			debounce.current = requestAnimationFrame(() => {
				if (mounted.current === true) {
					__setValue(localStorage.getItem(key) as T)
				} else {
					channel.current?.close()
					channel.current = undefined
				}
			})
		}

		if (channel.current === undefined) {
			channel.current = new BroadcastChannel(`storage:${key}`)
			channel.current.addEventListener('message', fn)
		}

		if (localStorage.getItem(key) === null) {
			if (initial !== null) {
				localStorage.setItem(key, initial)
			}
		}

		addEventListener('storage', fn)
		mounted.current = true
		fn()

		return () => {
			removeEventListener('storage', fn)
			mounted.current = false
			fn()
		}
	}, [])

	const setValue = (value: T | null) => {
		if (value === null) localStorage.removeItem(key)
		else localStorage.setItem(key, value)
		__setValue(value)
		channel.current?.postMessage(true)
	}

	return [value, setValue]
}
