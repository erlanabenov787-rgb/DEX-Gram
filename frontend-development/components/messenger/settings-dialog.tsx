'use client'

import { useState } from 'react'
import { Loader2, ShieldCheck, ShieldAlert, Wifi, WifiOff, ClipboardPaste, Server } from 'lucide-react'
import { IS_MOCK, SAMPLE_BOOTSTRAP_RESPONSE, parseBootstrapResponse, type Relay } from '@/lib/tauri'
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
  // Receives the parsed relay list to hand off to update_relays.
  onConnect: (relays: Relay[]) => Promise<void>
}) {
  const [raw, setRaw] = useState('')
  const [error, setError] = useState<string | null>(null)

  async function handleSubmit() {
    setError(null)
    let relays: Relay[]
    try {
      relays = parseBootstrapResponse(raw)
    } catch (e) {
      setError(typeof e === 'string' ? e : 'Could not parse the bootstrap response.')
      return
    }
    try {
      await onConnect(relays)
    } catch (e) {
      setError(typeof e === 'string' ? e : 'update_relays failed.')
    }
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
              <p
                className={`text-sm font-semibold ${
                  connected ? 'text-accent-foreground' : 'text-destructive'
                }`}
              >
                {connected ? 'Relay layer connected' : 'Relay layer not connected'}
              </p>
              <p
                className={`text-[13px] leading-snug ${
                  connected ? 'text-accent-foreground/80' : 'text-destructive/80'
                }`}
              >
                {connected
                  ? 'Messages can be sent and received.'
                  : 'You can browse, but nothing sends until this is up.'}
              </p>
            </div>
          </div>
        </div>

        {/* bootstrap connection form (only while disconnected) */}
        {!connected ? (
          <div className="flex flex-col gap-2.5">
            <div className="flex items-center justify-between gap-2">
              <label
                htmlFor="bootstrap-response"
                className="flex items-center gap-1.5 text-[13px] font-semibold text-foreground"
              >
                <Server className="size-3.5 text-muted-foreground" />
                Bootstrap server response
              </label>
              {IS_MOCK ? (
                <button
                  type="button"
                  onClick={() => {
                    setRaw(SAMPLE_BOOTSTRAP_RESPONSE)
                    setError(null)
                  }}
                  className="inline-flex items-center gap-1 rounded-full bg-muted px-2.5 py-1 text-[11px] font-medium text-muted-foreground transition-colors hover:text-foreground"
                >
                  <ClipboardPaste className="size-3" />
                  Paste sample
                </button>
              ) : null}
            </div>

            <p className="text-[12px] leading-relaxed text-muted-foreground text-pretty">
              Paste the relay list returned by your bootstrap server. It wires up the routing layer
              via <code className="rounded bg-muted px-1 py-0.5 text-[11px]">update_relays</code>.
            </p>

            <textarea
              id="bootstrap-response"
              value={raw}
              onChange={(e) => {
                setRaw(e.target.value)
                if (error) setError(null)
              }}
              spellCheck={false}
              rows={6}
              placeholder={'{\n  "relays": [\n    { "peer_id": "...", "multiaddr": "...", "onion_public_key": "..." }\n  ]\n}'}
              className="w-full resize-y rounded-xl border border-border bg-muted/40 px-3 py-2.5 font-mono text-[12px] leading-relaxed text-foreground outline-none transition-colors placeholder:text-muted-foreground/60 focus:border-primary/50 focus:bg-background"
            />

            {error ? (
              <p className="flex items-start gap-1.5 text-[12px] leading-snug text-destructive">
                <ShieldAlert className="mt-0.5 size-3.5 shrink-0" />
                <span className="text-pretty">{error}</span>
              </p>
            ) : null}

            <button
              type="button"
              onClick={handleSubmit}
              disabled={connecting || !raw.trim()}
              className="flex w-full items-center justify-center gap-2 rounded-xl bg-destructive py-2.5 text-sm font-semibold text-white transition-opacity hover:opacity-90 disabled:opacity-50"
            >
              {connecting ? <Loader2 className="size-4 animate-spin" /> : null}
              {connecting ? 'Wiring up relays…' : 'Connect'}
            </button>
          </div>
        ) : null}

        {/* explainer */}
        <div className="flex items-start gap-2.5 text-[13px] leading-relaxed text-muted-foreground">
          {connected ? (
            <ShieldCheck className="mt-0.5 size-4 shrink-0 text-primary" />
          ) : (
            <ShieldAlert className="mt-0.5 size-4 shrink-0 text-destructive" />
          )}
          <p className="text-pretty">
            Once the standalone bootstrap client is wired in, it fetches and applies this list
            automatically. Until then, paste the response by hand to bring routing online.
          </p>
        </div>

        {IS_MOCK ? (
          <p className="rounded-lg bg-muted px-3 py-2 text-[12px] leading-relaxed text-muted-foreground">
            Preview mode: running with mock data outside the Tauri shell. Inside the desktop app these
            calls hit the real Rust backend.
          </p>
        ) : null}
      </div>
    </Modal>
  )
}
