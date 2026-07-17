'use client'

import { useMemo, useState } from 'react'
import { MessagesSquare, Plus, QrCode, Search, Settings } from 'lucide-react'
import type { Contact, Me } from '@/lib/tauri'
import { truncateId } from '@/lib/messenger-utils'
import { Avatar } from './avatar'
import { ThemeToggle } from './theme-toggle'

export function ContactList({
  me,
  contacts,
  activeId,
  connected,
  onSelect,
  onAdd,
  onOpenIdentity,
  onOpenSettings,
}: {
  me: Me | null
  contacts: Contact[]
  activeId: string | null
  connected: boolean
  onSelect: (c: Contact) => void
  onAdd: () => void
  onOpenIdentity: () => void
  onOpenSettings: () => void
}) {
  const [query, setQuery] = useState('')

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return contacts
    return contacts.filter(
      (c) => c.display_name.toLowerCase().includes(q) || c.user_id.toLowerCase().includes(q),
    )
  }, [contacts, query])

  return (
    <div className="flex h-full flex-col bg-sidebar">
      {/* ── identity header ──────────────────────────────────────────────────
       *  safe-top-header: padding-top = max(env(safe-area-inset-top), 0.75rem)
       *  Это гарантирует что шапка всегда ниже системного статус-бара Android
       *  и под вырезом (notch), не залезая под иконки / часы.
       *  На обычных устройствах без notch padding остаётся равным 0.75rem.
       */}
      <header className="safe-top-header flex items-center gap-3 border-b border-border px-4">
        <button
          type="button"
          onClick={onOpenIdentity}
          title="Show my identity & QR"
          className="group relative shrink-0 rounded-full outline-none"
        >
          <span className="block rounded-full bg-gradient-to-br from-primary to-emerald-400 p-[2px]">
            <span className="flex size-9 items-center justify-center rounded-full bg-sidebar">
              <QrCode className="size-4 text-primary" />
            </span>
          </span>
          <span
            className={`absolute -right-0.5 -bottom-0.5 size-2.5 rounded-full border-2 border-sidebar ${
              connected ? 'bg-primary' : 'bg-destructive'
            }`}
          />
        </button>
        <div className="min-w-0 flex-1">
          <p className="text-[11px] font-medium tracking-wide text-muted-foreground">Your ID</p>
          <p className="truncate font-mono text-[13px] font-medium text-foreground">
            {me ? truncateId(me.user_id, 10, 8) : '—'}
          </p>
        </div>
        <ThemeToggle />
        <button
          type="button"
          onClick={onOpenSettings}
          aria-label="Settings"
          title="Settings & relay status"
          className="relative flex size-9 shrink-0 items-center justify-center rounded-full text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
        >
          <Settings className="size-[18px]" />
          {!connected ? (
            <span className="absolute right-1.5 top-1.5 size-2 rounded-full bg-destructive ring-2 ring-sidebar" />
          ) : null}
        </button>
      </header>

      {/* search */}
      <div className="px-3 pt-3 pb-1">
        <div className="flex items-center gap-2 rounded-xl bg-muted px-3 py-2">
          <Search className="size-4 shrink-0 text-muted-foreground" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search contacts"
            className="w-full bg-transparent text-sm text-foreground outline-none placeholder:text-muted-foreground"
          />
        </div>
      </div>

      {/* list */}
      <div className="scroll-slim flex-1 overflow-y-auto px-2 py-1">
        {filtered.length === 0 ? (
          <EmptyContacts hasContacts={contacts.length > 0} onAdd={onAdd} />
        ) : (
          <ul className="flex flex-col">
            {filtered.map((c) => {
              const active = c.user_id === activeId
              return (
                <li key={c.user_id}>
                  <button
                    type="button"
                    onClick={() => onSelect(c)}
                    className={`flex w-full items-center gap-3 rounded-xl px-2 py-2 text-left transition-colors ${
                      active ? 'bg-accent' : 'hover:bg-muted'
                    }`}
                  >
                    <Avatar seed={c.user_id} name={c.display_name} className="size-11 text-base" />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-[15px] font-semibold text-foreground">
                        {c.display_name}
                      </span>
                      <span className="block truncate font-mono text-[11px] text-muted-foreground">
                        {truncateId(c.user_id, 8, 8)}
                      </span>
                    </span>
                  </button>
                </li>
              )
            })}
          </ul>
        )}
      </div>

      {/* add contact — safe-bottom: отступ снизу под navigation bar */}
      <div className="safe-bottom border-t border-border px-3 pt-3">
        <button
          type="button"
          onClick={onAdd}
          className="flex w-full items-center justify-center gap-2 rounded-xl bg-primary py-2.5 text-sm font-semibold text-primary-foreground transition-opacity hover:opacity-90 active:scale-[0.99]"
        >
          <Plus className="size-4" />
          Add contact
        </button>
      </div>
    </div>
  )
}

function EmptyContacts({ hasContacts, onAdd }: { hasContacts: boolean; onAdd: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center px-6 py-16 text-center">
      <div className="mb-4 flex size-14 items-center justify-center rounded-2xl bg-accent text-primary">
        <MessagesSquare className="size-7" />
      </div>
      {hasContacts ? (
        <p className="text-sm text-muted-foreground">No contacts match your search.</p>
      ) : (
        <>
          <p className="text-[15px] font-semibold text-foreground">No contacts yet</p>
          <p className="mt-1 mb-4 text-sm leading-relaxed text-muted-foreground text-pretty">
            Add someone by their UserID or scan their QR card to start an encrypted conversation.
          </p>
          <button
            type="button"
            onClick={onAdd}
            className="inline-flex items-center gap-2 rounded-full bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground transition-opacity hover:opacity-90"
          >
            <Plus className="size-4" />
            Add your first contact
          </button>
        </>
      )}
    </div>
  )
}
