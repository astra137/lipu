import type { PageProps } from '$fresh/server.ts'
import WebauthnCreate from '../islands/WebauthnCreate.tsx'

export default function Home(_props: PageProps) {
	return (
		<div class='max-w-xl mx-auto px-4 py-4 flex flex-col'>
			<WebauthnCreate />
		</div>
	)
}
