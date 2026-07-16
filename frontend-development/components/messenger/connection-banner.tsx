'use client'

import { ShieldAlert } from 'lucide-react'

// Shown until update_relays has succeeded. Nothing can be sent or received
// before the routing layer is wired up, so this is a hard warning. Connecting
// requires the bootstrap response, so this routes into Settings rather than
// firing a call directly.
export function ConnectionBanner({ onConfigure }: { onConfigure: () => void }) {
  return (
    <div className="flex items-center gap-3 border-b border-destructive/25 bg-destructive/10 px-4 py-2.5 text-destructive">
      <ShieldAlert className="size-4 shrink-0" />
      <p className="min-w-0 flex-1 text-[13px] leading-snug">
        <span className="font-semibold">Not connected.</span>{' '}
        <span className="text-destructive/80">Messaging is offline until the relay layer is up.</span>
      </p>
      <button
        type="button"
        onClick={onConfigure}
        className="inline-flex shrink-0 items-center rounded-full bg-destructive px-3 py-1 text-xs font-semibold text-white transition-opacity hover:opacity-90"
      >
        Set up
      </button>
    </div>
  )
}
