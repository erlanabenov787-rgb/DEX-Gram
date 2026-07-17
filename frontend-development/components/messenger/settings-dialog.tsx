'use client'

import { useEffect, useState } from 'react'
import {
  Loader2,
  ShieldCheck,
  ShieldAlert,
  Wifi,
  WifiOff,
  Server,
  Link,
  Trash2,
} from 'lucide-react'
import { api, IS_MOCK, SAMPLE_BOOTSTRAP_URL } from '@/lib/tauri'
import { Modal } from './modal'

export function SettingsDialog({
  open,
  onClose,
  connected,
  connecting,
  onConnect,
}: {
  open: boolean
  onClose: () => void
  connected: boolean
  connecting: boolean
  onConnect: (bootstrapUrl: string) => Promise<void>
}) {
  const [url, setUrl] = useState('')
  const [savedUrl, setSavedUrl] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  // Загружаем сохранённый URL когда диалог открывается
  useEffect(() => {
    if (!open) return
    api.getBootstrapUrl().then((u) => {
      setSavedUrl(u)
      if (u && !url) setUrl(u)
    }).catch(() => {})
  }, [open]) // eslint-disable-line react-hooks/exhaustive-deps

  async function handleSubmit() {
    setError(null)
    const trimmed = url.trim()
    if (!trimmed) {
      setError('Вставьте ссылку на сервер.')
      return
    }
    if (!trimmed.startsWith('http://') && !trimmed.startsWith('https://')) {
      setError('Ссылка должна начинаться с http:// или https://')
      return
    }
    try {
      await onConnect(trimmed)
    } catch (e) {
      setError(typeof e === 'string' ? e : 'Не удалось подключиться к серверу.')
    }
  }

  async function handleClear() {
    try {
      await api.clearBootstrapUrl()
      setSavedUrl(null)
      setUrl('')
      setError(null)
    } catch {}
  }

  return (
    <Modal open={open} onClose={onClose} title="Settings" description="Network & routing status.">
      <div className="flex flex-col gap-4">

        {/* relay status card */}
        <div
          className={`rounded-2xl border p-4 ${
            connected ? 'border-primary/30 bg-accent' : 'border-destructive/30 bg-destructive/10'
          }`}
        >
          <div className="flex items-center gap-3">
            <div
              className={`flex size-10 shrink-0 items-center justify-center rounded-full ${
                connected ? 'bg-primary/15 text-primary' : 'bg-destructive/15 text-destructive'
              }`}
            >
              {connected ? <Wifi className="size-5" /> : <WifiOff className="size-5" />}
            </div>
            <div className="min-w-0 flex-1">
              <p className={`text-sm font-semibold ${connected ? 'text-accent-foreground' : 'text-destructive'}`}>
                {connected ? 'Routing layer connected' : 'Routing layer not connected'}
              </p>
              <p className={`text-[13px] leading-snug ${connected ? 'text-accent-foreground/80' : 'text-destructive/80'}`}>
                {connected
                  ? 'Messages can be sent and received.'
                  : 'Nothing sends until the server is reachable.'}
              </p>
            </div>
          </div>
        </div>

        {/* bootstrap URL form */}
        <div className="flex flex-col gap-2.5">
          <div className="flex items-center justify-between gap-2">
            <label
              htmlFor="bootstrap-url"
              className="flex items-center gap-1.5 text-[13px] font-semibold text-foreground"
            >
              <Server className="size-3.5 text-muted-foreground" />
              Bootstrap server link
            </label>
            {savedUrl ? (
              <button
                type="button"
                onClick={handleClear}
                title="Forget saved server"
                className="inline-flex items-center gap-1 rounded-full bg-muted px-2.5 py-1 text-[11px] font-medium text-muted-foreground transition-colors hover:text-destructive"
              >
                <Trash2 className="size-3" />
                Forget
              </button>
            ) : IS_MOCK ? (
              <button
                type="button"
                onClick={() => { setUrl(SAMPLE_BOOTSTRAP_URL); setError(null) }}
                className="inline-flex items-center gap-1 rounded-full bg-muted px-2.5 py-1 text-[11px] font-medium text-muted-foreground transition-colors hover:text-foreground"
              >
                <Link className="size-3" />
                Paste sample
              </button>
            ) : null}
          </div>

          <p className="text-[12px] leading-relaxed text-muted-foreground text-pretty">
            {connected && savedUrl
              ? 'Server saved. App connects automatically on every launch.'
              : 'Paste the link your contact shared. The app fetches relay nodes automatically — no manual JSON needed.'}
          </p>

          <div className="relative flex items-center">
            <input
              id="bootstrap-url"
              type="url"
              value={url}
              onChange={(e) => { setUrl(e.target.value); if (error) setError(null) }}
              onKeyDown={(e) => { if (e.key === 'Enter') handleSubmit() }}
              placeholder="http://your-friend-pc:8080"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
              className="w-full rounded-xl border border-border bg-muted/40 px-3 py-2.5 pr-9 text-sm text-foreground outline-none transition-colors placeholder:text-muted-foreground/60 focus:border-primary/50 focus:bg-background"
            />
            <Link className="pointer-events-none absolute right-3 size-3.5 text-muted-foreground/50" />
          </div>

          {error ? (
            <p className="flex items-start gap-1.5 text-[12px] leading-snug text-destructive">
              <ShieldAlert className="mt-0.5 size-3.5 shrink-0" />
              <span className="text-pretty">{error}</span>
            </p>
          ) : null}

          <button
            type="button"
            onClick={handleSubmit}
            disabled={connecting || !url.trim()}
            className="flex w-full items-center justify-center gap-2 rounded-xl bg-primary py-2.5 text-sm font-semibold text-primary-foreground transition-opacity hover:opacity-90 disabled:opacity-50"
          >
            {connecting ? <Loader2 className="size-4 animate-spin" /> : null}
            {connecting ? 'Connecting…' : connected ? 'Reconnect' : 'Connect'}
          </button>
        </div>

        {/* explainer */}
        <div className="flex items-start gap-2.5 text-[13px] leading-relaxed text-muted-foreground">
          {connected ? (
            <ShieldCheck className="mt-0.5 size-4 shrink-0 text-primary" />
          ) : (
            <ShieldAlert className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
          )}
          <p className="text-pretty">
            Messages are routed through an onion layer — the bootstrap server only provides the
            relay list, it never sees your messages or contacts.
          </p>
        </div>

        {IS_MOCK ? (
          <p className="rounded-lg bg-muted px-3 py-2 text-[12px] leading-relaxed text-muted-foreground">
            Preview mode: running with mock data outside the Tauri shell. Inside the app these
            calls hit the real Rust backend.
          </p>
        ) : null}
      </div>
    </Modal>
  )
}
