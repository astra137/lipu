import { assertEquals } from '$std/assert/mod.ts'
import { assertRejects } from '$std/assert/assert_rejects.ts'

// Linear vs tree
// Stateful vs functional
// Parallelism
// Memory efficiency
// Development ease

// Here is my problem solving method explained.
// We might call it Vibes Driven Development.

// I started with a rough draft:
// const a = queue([], () => {})
// const b = queue([a], () => {})
// const c = queue([a], () => {})

// Huh. This API reminds me of Promise.all.
// Promise chains are a lot like dependency trees. Let's try it.
// Promise.all as a template:
// all<T extends readonly unknown[]>(values: T): Promise<{ [P in keyof T]: Awaited<T[P]>; }>;

Deno.test('promise graph with chain function', async () => {
	async function chain<T extends readonly unknown[], V>(
		deps: { [P in keyof T]: Promise<T[P]> },
		run: (...args: { [P in keyof T]: Awaited<T[P]> }) => V | Promise<V>,
	) {
		return await run(...await Promise.all(deps))
	}

	const a = chain([], () => 'a')
	const b = chain([a], (a) => `${a}b`)
	const c = chain([a], (a) => `${a}c`)
	const d = chain([b, c], (b, c) => `${b}${c}d`)
	assertEquals(await d, 'abacd')
})

// That quickly became a convenience wrapper around Promise.all.
// To me, that's a bad sign--JavaScript trying not to be JavaScript.
// Let's find out. What if we tried to make it more "vanilla"?

Deno.test('promise graph with plain IIFEs', async () => {
	const a = (() => Promise.resolve('a'))()
	const b = (async () => `${await a}b`)()
	const c = (async () => `${await a}c`)()
	const d = (async () => `${await b}${await c}d`)()
	assertEquals(await d, 'abacd')
})

// Vibes Driven Development is working. I learned something important.
// Hiding Promise.all wasn't the real reason for the chain function.
// It was memoization. I am designing for a task to run once.
// Memoization in JavaScript is tedious and usually provided by libraries.
// React offers functional components the useMemo hook, for example.
// Let's find out. What if we tried to focus on memoization?

Deno.test('promise graph with memoization', async () => {
	function memoize<T>(run: () => Promise<T>) {
		let promise: Promise<T>
		return () => {
			promise ??= run()
			return promise
		}
	}

	const a = memoize(async () => await Promise.resolve('a'))
	const b = memoize(async () => `${await a()}b`)
	const c = memoize(async () => `${await a()}c`)
	const d = memoize(async () => `${await b()}${await c()}d`)
	assertEquals(await d(), 'abacd')

	const e = memoize(async () => await Promise.reject(new Error()))
	const f = memoize(async () => `${await e()}f`)
	await assertRejects(async () => await f())
})

// I'm curious about the ergonomics of calling the dependencies.
// I was reminded of a library I used once: sindresorhus/p-lazy.
// Lazy promises act as memoizers and also offer familiar promise syntax.

Deno.test('promise graph with lazy promises', async () => {
	function lazy<T>(executor: () => PromiseLike<T>): PromiseLike<T> {
		let promise: PromiseLike<T>
		return {
			// biome-ignore lint/suspicious/noThenProperty: proof of concept
			then<T1, T2>(
				onfulfilled?: ((value: T) => T1 | PromiseLike<T1>) | null,
				onrejected?: ((reason: unknown) => T2 | PromiseLike<T2>) | null,
			) {
				promise ??= executor()
				return promise.then(onfulfilled, onrejected)
			},
		}
	}

	const a = lazy(async () => await Promise.resolve('a'))
	const b = lazy(async () => `${await a}b`)
	const c = lazy(async () => `${await a}c`)
	const d = lazy(async () => `${await b}${await c}d`)
	assertEquals(await d, 'abacd')

	const e = lazy(async () => await Promise.reject(new Error()))
	const f = lazy(async () => `${await e}f`)
	await assertRejects(async () => await f)
})

// Hmm. The vibes are off again, and for the same reason as before.
// Conclusion: if it looks like a promise, it must act like a promise.
// Which means tasks must have a different interface than promises.
// Also, I let a false requirement sneak into the design: lazy evaluation.
// But the real requirement is that tasks run after dependencies are satisfied.

Deno.test('prototype tasks', async () => {
	function queue<T>(fn: () => PromiseLike<T>): PromiseLike<T> {
		return Promise.resolve().then(fn)
	}

	const t1 = queue(async () => {
		return await Promise.resolve(1)
	})

	const t2 = queue(async () => {
		return await t1 + await Promise.resolve(2)
	})

	const t3 = queue(async () => {
		return await t2 + await Promise.reject(new Error('task 3 failed'))
	})

	const t4 = queue(async () => {
		return await t2 + await t3
	})

	const t5 = queue(() => {
		throw new Error('task 5 failed')
	})

	const errors = await Promise.all(
		[t1, t2, t3, t4, t5].map((p) =>
			p.then(() => undefined, (reason) => String(reason))
		),
	)

	assertEquals(errors, [
		undefined,
		undefined,
		'Error: task 3 failed',
		'Error: task 3 failed',
		'Error: task 5 failed',
	])
})

// Ugh. This feels over-engineered now.
// This an old enemy of mine.
// How does one comfortably introspect async work in JavaScript?
