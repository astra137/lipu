import { loadMetadataBlob } from './blob.ts'

Deno.test('empty cache', async () => {
	await caches.delete('MDS3')
})

Deno.test('loadMetadataBlob', async () => {
	const payload = await loadMetadataBlob()
	console.log(payload.no)
	console.log(payload.nextUpdate)
})

Deno.test('EDIT: download as blob.json', async () => {
	const payload = await loadMetadataBlob()
	await Deno.writeFile(
		new URL('blob.json', import.meta.url),
		new TextEncoder().encode(JSON.stringify(payload)),
	)
})
