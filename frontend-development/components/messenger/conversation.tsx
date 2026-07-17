'use client'

import { useEffect, useRef, useState } from 'react'
import { ArrowLeft, Loader2, Send, ShieldAlert, TriangleAlert } from 'lucide-react'
import { api, type Contact, type HistoryItem } from '@/lib/tauri'
import { dayKey, formatDayLabel, formatTime, truncateId } from '@/lib/messenger-utils'
import { Avatar } from './avatar'

type PendingItem = HistoryItem & { pending?: boolean; failed?: boolean; localId?: string }

export function Conversation({
  contact,
  connected,
  reloadSignal,
  onBack,
}: {
  contact: Contact
  connected: boolean
  reloadSignal: number
  onBack: () => void
}) {
  const [messages, setMessages] = useState<PendingItem[]>([])
  const [loading, setLoading] = useState(true)
  const [text, setText] = useState('')
  const [sending, setSending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const scrollRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  // (Re)load history whenever the contact changes or a real-time event bumps
  // the reload signal from the parent.
  useEffect(() => {
    let cancelled = false
    setLoading(true)
    api
      .getHistory(contact.user_id, 200)
      .then((h) => {
        if (!cancelled) setMessages(h)
      })
      .catch((e) => {
        if (!cancelled) setError(String(e))
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [contact.user_id, reloadSignal])

  // Keep pinned to the newest message.
  useEffect(() => {
    const el = scrollRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [messages, loading])

  async function handleSend() {
    const value = text.trim()
    if (!value || sending) return
    setError(null)
    setText('')

    const localId = `local-${Date.now()}`
    const optimistic: PendingItem = {
      direction: 'sent',
      text: value,
      sent_at: Math.floor(Date.now() / 1000),
      pending: true,
      localId,
    }
    setMessages((m) => [...m, optimistic])
    setSending(true)

    try {
      await api.sendMessage(contact.user_id, value)
      // Reload authoritative history from the backend.
      const fresh = await api.getHistory(contact.user_id, 200)
      setMessages(fresh)
    } catch (e) {
      // Mark the optimistic bubble as failed and restore the draft.
      setMessages((m) =>
        m.map((msg) => (msg.localId === localId ? { ...msg, pending: false, failed: true } : msg)),
      )
      setError(String(e))
      setText(value)
    } finally {
      setSending(false)
      inputRef.current?.focus()
    }
  }

  function onKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'Enter' && !e.nativeEvent.isComposing && e.keyCode !== 229) {
      e.preventDefault()
      handleSend()
    }
  }

  return (
    <div className="flex h-full flex-col bg-background">
      {/* header */}
      <header className="flex items-center gap-3 border-b border-border bg-card px-3 py-2.5">
        <button
          type="button"
          onClick={onBack}
          aria-label="Back to contacts"
          className="flex size-9 items-center justify-center rounded-full text-muted-foreground transition-colors hover:bg-muted hover:text-foreground md:hidden"
        >
          <ArrowLeft className="size-5" />
        </button>
        <Avatar seed={contact.user_id} name={contact.display_name} className="size-9 text-sm" />
        <div className="min-w-0 flex-1">
          <p className="truncate text-[15px] font-semibold text-foreground">{contact.display_name}</p>
          <p className="truncate font-mono text-[11px] text-muted-foreground">
            {truncateId(contact.user_id, 10, 10)}
          </p>
        </div>
        <span className="hidden items-center gap-1.5 rounded-full bg-accent px-2.5 py-1 text-[11px] font-medium text-accent-foreground sm:inline-flex">
          <ShieldAlert className="size-3.5" />
          End-to-end
        </span>
      </header>

      {/* messages */}
      <div ref={scrollRef} className="scroll-slim flex-1 overflow-y-auto px-3 py-4 sm:px-6">
        {loading ? (
          <div className="flex h-full items-center justify-center text-muted-foreground">
            <Loader2 className="size-5 animate-spin" />
          </div>
        ) : messages.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center text-center text-muted-foreground">
            <p className="text-sm">No messages yet.</p>
            <p className="mt-1 text-xs">Say hello — everything here is end-to-end encrypted.</p>
          </div>
        ) : (
          <ul className="mx-auto flex max-w-2xl flex-col gap-1.5">
            {messages.map((m, i) => {
              const prev = messages[i - 1]
              const showDay = !prev || dayKey(prev.sent_at) !== dayKey(m.sent_at)
              return (
                <li key={m.localId ?? `${m.sent_at}-${i}`} className="contents">
                  {showDay ? (
                    <div className="my-2 flex justify-center">
                      <span className="rounded-full bg-muted px-2.5 py-0.5 text-[11px] font-medium text-muted-foreground">
                        {formatDayLabel(m.sent_at)}
                      </span>
                    </div>
                  ) : null}
                  <MessageBubble item={m} />
                </li>
              )
            })}
          </ul>
        )}
      </div>

      {/* error strip */}
      {error ? (
        <div className="flex items-center gap-2 border-t border-destructive/25 bg-destructive/10 px-4 py-2 text-[13px] text-destructive">
          <TriangleAlert className="size-4 shrink-0" />
          <span className="min-w-0 flex-1 truncate">{error}</span>
        </div>
      ) : null}

      {/* composer */}
      <div className="border-t border-border bg-card px-3 py-3">
        <div className="mx-auto flex max-w-2xl items-end gap-2">
          <input
            ref={inputRef}
            value={text}
            onChange={(e) => setText(e.target.value)}
            onKeyDown={onKeyDown}
            placeholder={connected ? 'Message…' : 'Connect the relay layer to send'}
            autoComplete="off"
            className="min-w-0 flex-1 rounded-2xl border border-transparent bg-muted px-4 py-2.5 text-[15px] text-foreground outline-none transition-colors placeholder:text-muted-foreground focus:border-primary"
          />
          <button
            type="button"
            onClick={handleSend}
            disabled={!text.trim() || sending}
            aria-label="Send message"
            className="flex size-11 shrink-0 items-center justify-center rounded-full bg-primary text-primary-foreground transition-all hover:opacity-90 active:scale-95 disabled:opacity-40"
          >
            {sending ? <Loader2 className="size-5 animate-spin" /> : <Send className="size-5" />}
          </button>
        </div>
      </div>
    </div>
  )
}

function MessageBubble({ item }: { item: PendingItem }) {
  const sent = item.direction === 'sent'
  return (
    <div className={`flex ${sent ? 'justify-end' : 'justify-start'}`}>
      <div
        className={[
          'max-w-[80%] rounded-2xl px-3.5 py-2 text-[15px] leading-relaxed break-words shadow-sm',
          sent
            ? 'rounded-br-md bg-primary text-primary-foreground'
            : 'rounded-bl-md bg-card text-card-foreground border border-border',
          item.pending ? 'opacity-70' : '',
          item.failed ? 'ring-1 ring-destructive/60' : '',
        ].join(' ')}
      >
        <span className="whitespace-pre-wrap">{item.text}</span>
        <span
          className={`mt-1 flex items-center justify-end gap-1 text-[10px] ${
            sent ? 'text-primary-foreground/70' : 'text-muted-foreground'
          }`}
        >
          {item.failed ? (
            <span className="font-medium text-destructive">Failed</span>
          ) : item.pending ? (
            <span>Sending…</span>
          ) : (
            formatTime(item.sent_at)
          )}
        </span>
      </div>
    </div>
  )
}
