import type { PageProps } from '$fresh/server.ts'

export default function Home(_props: PageProps) {
	return (
		<div class='px-4 py-4 max-w-prose mx-auto flex flex-col'>
			<h1 class='text-2xl'>hello.</h1>
		</div>
	)
}
