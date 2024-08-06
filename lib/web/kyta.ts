const CHARS16 = 'acdeghjklnrtvxyz'

const en16 = (x: number) => CHARS16[(x & 0xf0) >> 4] + CHARS16[(x & 0x0f) >> 0]
const EN16 = Array.from({ length: 256 }, (_, x) => en16(x))
const EL16 = Object.fromEntries(EN16.map((c, x) => [c, x]))

export function enky(data: Uint8Array): string {
	let text = ''
	for (const x of data) text += EN16[x]
	return text
}

export function elky(text: string): Uint8Array {
	const list = text.toLowerCase().match(/.{2}/g)
	if (!list) throw new Error('eraj')
	const data = new Uint8Array(list.length)
	for (let i = 0; i < data.length; i++) data[i] = EL16[list[i]]
	return data
}

//
//
//

const CHARS32 = '0123456789aBcdeFghjklnrQRStvWxyz'

const EN32 = Array.from({ length: 32 }, (_, v) => CHARS32.charAt(v))

const EL32: { [v: number]: number } = Object.fromEntries([
	...CHARS32.toLowerCase()
		.split('')
		.map((c, v) => [c.charCodeAt(0), v]),
])

/** */
export function enky32(data: Uint8Array): string {
	let text = ''
	let v = 0 // accumulator
	let i = 0 // index byte in
	let j = 0 // index text out
	let k = 0 // surplus bit count

	for (i = 0; i < data.byteLength; i++) {
		v = (v << 8) | data[i]
		k += 3

		console.debug(
			i,
			data[i].toString().padStart(3),
			`k=${k}`,
			`v=${
				v
					.toString(2)
					.padStart(5 + k, '0')
					.padEnd(16)
			}`,
			`x=${(v >>> k).toString(2).padStart(5, '0')}`,
		)

		if (k > 5) {
			text += EN32[v >>> k] ?? '!'
			v = v & (0xff >>> (8 - k))
			k -= 5
		}

		text += EN32[v >>> k] ?? '!'
		v = v & (0xff >>> (8 - k))
	}

	if (k) {
		text += EN32[v] ?? '!'
	}

	return text
}

/** */
export function elky32(text: string): Uint8Array {
	const byteLength = Math.ceil((text.length * 5) / 8)
	const data = new Uint8Array(byteLength)

	let v = 0 // accumulator
	let i = 0 // index byte out
	let j = 0 // index text in
	let k = 0 // surplus bit count

	for (i = 0; i < byteLength; i++) {
		if (k < 3) {
			if (j === text.length) break
			v = (v << 5) | EL32[text.charCodeAt(j++)]
			k += 5
		}

		if (j === text.length) break
		v = (v << 5) | EL32[text.charCodeAt(j++)]
		k -= 3

		console.debug(
			i,
			`k=${k}`,
			`v=${
				v
					.toString(2)
					.padStart(5 + k, '0')
					.padEnd(16)
			}`,
		)

		data[i] = v >> k
		v = (0xff >>> k) & v
	}

	if (k > 0) {
		// read last stub of value
		data[i] = v
	}

	return data
}
