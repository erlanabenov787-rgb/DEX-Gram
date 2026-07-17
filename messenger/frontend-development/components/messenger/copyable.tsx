'use client'

import { useState } from 'react'
import { Check, Copy } from 'lucide-react'
import { truncateId } from '@/lib/messenger-utils'
import { cn } from '@/lib/utils'

// A monospace value that shows a truncated form and reveals / copies the full
// string on tap — used for UserIDs and public keys, which are long hex strings.
export function Copyable({
  value,
  display,
  className,
  full = false,
}: {
  value: string
  display?: string
  className?: string
  full?: boolean
}) {
  const [copied, setCopied] = useState(false)
  const [revealed, setRevealed] = useState(full)

  async function handleClick() {
    if (!revealed) {
      setRevealed(true)
    }
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      setTimeout(() => setCopied(false), 1400)
    } catch {
      /* clipboard may be unavailable — revealing is still useful */
    }
  }

  return (
    <button
      type="button"
      onClick={handleClick}
      title="Tap to reveal & copy"
      className={cn(
        'group inline-flex max-w-full items-center gap-1.5 font-mono text-muted-foreground transition-colors hover:text-foreground',
        className,
      )}
    >
      <span className={cn('truncate', revealed && 'break-all')}>
        {revealed ? value : (display ?? truncateId(value))}
      </span>
      {copied ? (
        <Check className="size-3.5 shrink-0 text-primary" />
      ) : (
        <Copy className="size-3.5 shrink-0 opacity-0 transition-opacity group-hover:opacity-60" />
      )}
    </button>
  )
}
