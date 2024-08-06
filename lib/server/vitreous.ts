import crypto from 'crypto'
import b64u from 'b64u'

const refract = (initial: Buffer, ...array: Buffer[]) => {
	return array.reduce(
		(k, m) => crypto.createHmac('sha256', k).update(m).digest(),
		initial,
	)
}

export function dop(gem: string) {
	return gem.split('.').map((x) => b64u.toBuffer(x))
}

export function lap(...facets: Buffer[]) {
	return facets.map((x) => b64u.encode(x)).join('.')
}

export function illuminate(lux: string, ...facets: Buffer[]) {
	const secret = b64u.toBuffer(lux)
	const fire = refract(secret, ...facets)
	return lap(...facets, fire)
}

export function engrave(gem: string, ...additions: Buffer[]) {
	const facets = dop(gem)
	const culet = facets.pop()!
	const fire = refract(culet, ...additions)
	return lap(...facets, ...additions, fire)
}

export function scintillate(lux: string, gem: string) {
	const secret = b64u.toBuffer(lux)
	const facets = dop(gem)
	const actual = facets.pop()!
	const expect = refract(secret, ...facets)
	if (Buffer.compare(actual, expect) !== 0) throw new Error()
	return facets
}
