import { encodeHex } from '$std/encoding/hex.ts'

function replacer(_key: string, value: unknown) {
	if (value instanceof Uint8Array) {
		return `Uint8Array(${value.length}) ${encodeHex(value)}`
	}

	if (value instanceof Map) {
		return `Map(${value.size}) {${[...value.keys()]}}`
	}

	return value
}

type Props = {
	data: unknown
	summary: string
}

export function CodeJson(props: Props) {
	const json = JSON.stringify(props.data, replacer, '\t')
	return (
		<details open>
			<summary>
				<code>{props.summary}</code>
			</summary>
			<pre class='text-gray-500'><code>{json}</code></pre>
		</details>
	)
}
