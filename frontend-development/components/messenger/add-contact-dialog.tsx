'use client'

import { useState } from 'react'
import { Check, Loader2, Search, TriangleAlert } from 'lucide-react'
import { api } from '@/lib/tauri'
import { Modal } from './modal'

const PUBKEY_LEN = 64

export function AddContactDialog({
  open,
  onClose,
  onAdded,
}: {
  open: boolean
  onClose: () => void
  onAdded: () => void
}) {
  const [userId, setUserId] = useState('')
  const [name, setName] = useState('')
  const [pubKey, setPubKey] = useState('')

  const [looking, setLooking] = useState(false)
  const [lookupOk, setLookupOk] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  function reset() {
    setUserId('')
    setName('')
    setPubKey('')
    setLooking(false)
    setLookupOk(false)
    setSaving(false)
    setError(null)
  }

  function close() {
    reset()
    onClose()
  }

  async function handleLookup() {
    const id = userId.trim()
    if (!id) {
      setError('Enter a UserID to search for.')
      return
    }
    setError(null)
    setLookupOk(false)
    setLooking(true)
    try {
      const found = await api.lookupUser(id)
      setPubKey(found.public_key_hex)
      setLookupOk(true)
    } catch (e) {
      setError(String(e))
    } finally {
      setLooking(false)
    }
  }

  async function handleAdd() {
    const id = userId.trim()
    const displayName = name.trim()
    const key = pubKey.trim()
    if (!displayName) return setError('Give this contact a display name.')
    if (!id) return setError('UserID is required.')
    if (key.length !== PUBKEY_LEN) return setError(`Public key must be ${PUBKEY_LEN} hex characters.`)

    setError(null)
    setSaving(true)
    try {
      await api.addContact(id, displayName, key)
      onAdded()
      close()
    } catch (e) {
      setError(String(e))
      setSaving(false)
    }
  }

  const keyLen = pubKey.trim().length

  return (
    <Modal
      open={open}
      onClose={close}
      title="Add contact"
      description="Look someone up on the network by UserID, or paste both fields if they shared their card out of band."
    >
      <div className="flex flex-col gap-3">
        <Field label="Display name">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Nadia"
            className="w-full rounded-xl border border-transparent bg-muted px-3.5 py-2.5 text-sm text-foreground outline-none transition-colors placeholder:text-muted-foreground focus:border-primary"
          />
        </Field>

        <Field label="UserID">
          <div className="flex items-center gap-2">
            <input
              value={userId}
              onChange={(e) => {
                setUserId(e.target.value)
                setLookupOk(false)
              }}
              placeholder="hex fingerprint"
              className="w-full min-w-0 rounded-xl border border-transparent bg-muted px-3.5 py-2.5 font-mono text-[13px] text-foreground outline-none transition-colors placeholder:text-muted-foreground focus:border-primary"
            />
            <button
              type="button"
              onClick={handleLookup}
              disabled={looking}
              className="inline-flex shrink-0 items-center gap-1.5 rounded-xl bg-secondary px-3 py-2.5 text-sm font-medium text-secondary-foreground transition-colors hover:bg-accent disabled:opacity-60"
            >
              {looking ? (
                <Loader2 className="size-4 animate-spin" />
              ) : lookupOk ? (
                <Check className="size-4 text-primary" />
              ) : (
                <Search className="size-4" />
              )}
              <span className="hidden sm:inline">{looking ? 'Searching' : 'Find'}</span>
            </button>
          </div>
          {looking ? (
            <p className="mt-1.5 text-xs text-muted-foreground">
              Searching the DHT network — this can take up to 30 seconds…
            </p>
          ) : null}
        </Field>

        <Field label="Public key">
          <input
            value={pubKey}
            onChange={(e) => setPubKey(e.target.value)}
            placeholder="64 hex characters"
            className="w-full rounded-xl border border-transparent bg-muted px-3.5 py-2.5 font-mono text-[13px] text-foreground outline-none transition-colors placeholder:text-muted-foreground focus:border-primary"
          />
          <p
            className={`mt-1.5 text-xs ${
              keyLen === 0
                ? 'text-muted-foreground'
                : keyLen === PUBKEY_LEN
                  ? 'text-primary'
                  : 'text-destructive'
            }`}
          >
            {keyLen === 0
              ? 'Auto-filled after a successful search, or paste it manually.'
              : `${keyLen} / ${PUBKEY_LEN} characters`}
          </p>
        </Field>

        {error ? (
          <div className="flex items-start gap-2 rounded-xl bg-destructive/10 px-3 py-2 text-[13px] text-destructive">
            <TriangleAlert className="mt-0.5 size-4 shrink-0" />
            <span className="min-w-0 break-words">{error}</span>
          </div>
        ) : null}

        <div className="mt-1 flex gap-2">
          <button
            type="button"
            onClick={close}
            className="flex-1 rounded-xl bg-secondary py-2.5 text-sm font-semibold text-secondary-foreground transition-colors hover:bg-accent"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleAdd}
            disabled={saving}
            className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-primary py-2.5 text-sm font-semibold text-primary-foreground transition-opacity hover:opacity-90 disabled:opacity-60"
          >
            {saving ? <Loader2 className="size-4 animate-spin" /> : null}
            Add contact
          </button>
        </div>
      </div>
    </Modal>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-[13px] font-medium text-foreground">{label}</span>
      {children}
    </label>
  )
}
