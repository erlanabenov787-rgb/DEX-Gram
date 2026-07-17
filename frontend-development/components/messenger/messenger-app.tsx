'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import { MessagesSquare } from 'lucide-react'
import {
  api,
  onMessageReceived,
  type Contact,
  type Me,
} from '@/lib/tauri'
import { ContactList } from './contact-list'
import { Conversation } from './conversation'
import { AddContactDialog } from './add-contact-dialog'
import { IdentityDialog } from './identity-dialog'
import { SettingsDialog } from './settings-dialog'
import { ConnectionBanner } from './connection-banner'

export function MessengerApp() {
  const [me, setMe] = useState<Me | null>(null)
  const [contacts, setContacts] = useState<Contact[]>([])
  const [active, setActive] = useState<Contact | null>(null)
  const [reloadSignal, setReloadSignal] = useState(0)

  const [connected, setConnected] = useState(false)
  const [connecting, setConnecting] = useState(false)

  const [addOpen, setAddOpen] = useState(false)
  const [identityOpen, setIdentityOpen] = useState(false)
  const [settingsOpen, setSettingsOpen] = useState(false)

  // Keep a ref to the active contact so the (once-registered) event listener
  // always sees the current selection without being re-subscribed.
  const activeRef = useRef<Contact | null>(null)
  activeRef.current = active

  const loadContacts = useCallback(async () => {
    try {
      setContacts(await api.listContacts())
    } catch (e) {
      console.log('[messenger] list_contacts failed:', e)
    }
  }, [])

  // Startup: identity + contacts.
  useEffect(() => {
    api
      .getMe()
      .then(setMe)
      .catch((e) => console.log('[messenger] get_me failed:', e))
    loadContacts()
  }, [loadContacts])

  // Real-time inbound messages. Registered once; unlistens on unmount.
  useEffect(() => {
    let dispose: (() => void) | undefined
    let cancelled = false
    onMessageReceived((payload) => {
      // A message may arrive from someone not yet in the list.
      loadContacts()
      if (activeRef.current && activeRef.current.user_id === payload.from_user_id) {
        setReloadSignal((n) => n + 1)
      }
    }).then((unlisten) => {
      if (cancelled) unlisten()
      else dispose = unlisten
    })
    return () => {
      cancelled = true
      dispose?.()
    }
  }, [loadContacts])

  // Bootstrap URL flow: save URL → Rust fetches relay list automatically.
  const handleConnect = useCallback(
    async (bootstrapUrl: string) => {
      if (connecting) return
      setConnecting(true)
      try {
        await api.setBootstrapUrl(bootstrapUrl)
        setConnected(true)
        setSettingsOpen(false)
      } catch (e) {
        console.log('[messenger] set_bootstrap_url failed:', e)
        throw e
      } finally {
        setConnecting(false)
      }
    },
    [connecting],
  )

  return (
    <main className="flex h-dvh w-full overflow-hidden bg-background text-foreground">
      {/* sidebar / contact list */}
      <aside
        className={`h-full w-full shrink-0 border-r border-border md:w-[340px] lg:w-[380px] ${
          active ? 'hidden md:block' : 'block'
        }`}
      >
        <ContactList
          me={me}
          contacts={contacts}
          activeId={active?.user_id ?? null}
          connected={connected}
          onSelect={setActive}
          onAdd={() => setAddOpen(true)}
          onOpenIdentity={() => setIdentityOpen(true)}
          onOpenSettings={() => setSettingsOpen(true)}
        />
      </aside>

      {/* detail / conversation */}
      <section className={`h-full min-w-0 flex-1 flex-col ${active ? 'flex' : 'hidden md:flex'}`}>
        {!connected ? <ConnectionBanner onConfigure={() => setSettingsOpen(true)} /> : null}
        <div className="min-h-0 flex-1">
          {active ? (
            <Conversation
              contact={active}
              connected={connected}
              reloadSignal={reloadSignal}
              onBack={() => setActive(null)}
            />
          ) : (
            <EmptyConversation />
          )}
        </div>
      </section>

      <AddContactDialog
        open={addOpen}
        onClose={() => setAddOpen(false)}
        onAdded={loadContacts}
      />
      <IdentityDialog open={identityOpen} onClose={() => setIdentityOpen(false)} me={me} />
      <SettingsDialog
        open={settingsOpen}
        onClose={() => setSettingsOpen(false)}
        connected={connected}
        connecting={connecting}
        onConnect={handleConnect}
      />
    </main>
  )
}

function EmptyConversation() {
  return (
    <div className="flex h-full flex-col items-center justify-center bg-background px-8 text-center">
      <div className="mb-5 flex size-16 items-center justify-center rounded-3xl bg-accent text-primary">
        <MessagesSquare className="size-8" />
      </div>
      <h2 className="text-lg font-semibold text-foreground">Select a conversation</h2>
      <p className="mt-1.5 max-w-xs text-sm leading-relaxed text-muted-foreground text-pretty">
        Choose a contact on the left to open an end-to-end encrypted chat, or add someone new.
      </p>
    </div>
  )
}
