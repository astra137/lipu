import type { JSX } from 'preact'
import { IS_BROWSER } from '$fresh/runtime.ts'

export function Button(props: JSX.HTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      {...props}
      disabled={!IS_BROWSER || props.disabled}
      class='px-2 py-2 bg-transparent font-semibold rounded border border-gray-600 hover:border-green-600 hover:text-green-600 cursor-pointer'
    />
  )
}
