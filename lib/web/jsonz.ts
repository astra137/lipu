import {
	decodeBase64Url,
	encodeBase64Url,
} from 'https://deno.land/std@0.224.0/encoding/base64url.ts'

/** JSON.stringify replacer that encodes certain values as data URIs. */
export function replacer(_key: string, value: unknown) {
	if (value instanceof Uint8Array) return `\u200B${encodeBase64Url(value)}`
	if (typeof value === 'bigint') return `\u200B\u200B${value}`
	return value
}

/** JSON.parse reviver that decodes certain data URIs into values. */
export function reviver(_key: string, value: unknown) {
	if (typeof value === 'string') {
		const match = value.match(/^(\u200B+)([\w-]*)$/)
		if (match) {
			const [, tag, data] = match as [never, string, string]
			switch (tag.length) {
				case 1:
					return decodeBase64Url(data)
				case 2:
					return BigInt(data)
			}
		}
	}

	return value
}
