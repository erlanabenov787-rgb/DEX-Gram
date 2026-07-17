// Bridge between the frontend and the Tauri (Rust) backend.
//
// Inside the Tauri webview these calls go through `@tauri-apps/api` to the real
// Rust commands. In a plain browser (the v0 preview, `next dev` in a tab) there
// is no Tauri IPC, so we transparently fall back to an in-memory mock. This lets
// the whole UI be designed and exercised without spinning up the desktop shell,
// and the exact same component code runs unchanged in production.

export type Me = { user_id: string; public_key_hex: string }
export type Contact = { user_id: string; display_name: string }
export type Direction = "sent" | "received"
export type HistoryItem = { direction: Direction; text: string; sent_at: number }
export type Relay = { peer_id: string; multiaddr: string; onion_public_key: string }
export type MessageReceived = { from_user_id: string; text: string }

// Are we actually running inside a Tauri webview?
export function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window
}

// ---------------------------------------------------------------------------
// Real backend (Tauri)
// ---------------------------------------------------------------------------

async function realInvoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  const { invoke } = await import("@tauri-apps/api/core")
  return invoke<T>(cmd, args)
}

async function realListen(
  event: string,
  handler: (payload: MessageReceived) => void,
): Promise<() => void> {
  const { listen } = await import("@tauri-apps/api/event")
  return listen<MessageReceived>(event, (e) => handler(e.payload))
}

// ---------------------------------------------------------------------------
// Mock backend (browser preview)
// ---------------------------------------------------------------------------

function randomHex(len: number): string {
  const chars = "0123456789abcdef"
  let out = ""
  for (let i = 0; i < len; i++) out += chars[Math.floor(Math.random() * chars.length)]
  return out
}

const mockMe: Me = {
  user_id: "a3f7c2e91b04d8a6f5e2c7b90a1d4e6f8c3b2a1907e5d4c3b2a1f09e8d7c6b5a",
  public_key_hex: "9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d",
}

const mockRelays: Relay[] = [
  {
    peer_id: "12D3KooWQ8b7f2aE",
    multiaddr: "/onion3/abcdef123456:1042",
    onion_public_key: randomHex(64),
  },
]

type MockState = {
  contacts: Contact[]
  history: Record<string, HistoryItem[]>
  connected: boolean
  bootstrapUrl: string | null
  listeners: Set<(payload: MessageReceived) => void>
}

function nowSec() {
  return Math.floor(Date.now() / 1000)
}

const g = globalThis as unknown as { __messengerMock?: MockState }

function mockState(): MockState {
  if (!g.__messengerMock) {
    const contacts: Contact[] = [
      { user_id: "7b2c9e1f4a6d8b3c5e7f9a0b2d4c6e8f1a3b5c7d9e0f2a4b6c8d0e2f4a6b8c0d", display_name: "Nadia" },
      { user_id: "f0e9d8c7b6a5948372615049382716f5e4d3c2b1a0918273645564738291a0b1", display_name: "Marat" },
      { user_id: "1122334455667788990011223344556677889900aabbccddeeff00112233abcd", display_name: "Echo (demo)" },
    ]
    g.__messengerMock = {
      contacts,
      connected: false,
      bootstrapUrl: null,
      listeners: new Set(),
      history: {
        [contacts[0].user_id]: [
          { direction: "received", text: "hey, did the key exchange go through?", sent_at: nowSec() - 3600 },
          { direction: "sent", text: "yeah, we're end to end now", sent_at: nowSec() - 3540 },
          { direction: "received", text: "nice. this thing actually feels private", sent_at: nowSec() - 3500 },
        ],
        [contacts[1].user_id]: [
          { direction: "sent", text: "sent you the relay config", sent_at: nowSec() - 7200 },
          { direction: "received", text: "got it, connected 👍", sent_at: nowSec() - 7100 },
        ],
        [contacts[2].user_id]: [
          { direction: "sent", text: "test", sent_at: nowSec() - 100 },
          { direction: "received", text: "test", sent_at: nowSec() - 99 },
        ],
      },
    }
  }
  return g.__messengerMock!
}

function mockListen(
  _event: string,
  _handler: (payload: MessageReceived) => void,
): Promise<() => void> {
  const state = mockState()
  state.listeners.add(_handler)
  return Promise.resolve(() => state.listeners.delete(_handler))
}

// ---------------------------------------------------------------------------
// Unified API surface
// ---------------------------------------------------------------------------

export const api = {
  getMe(): Promise<Me> {
    if (isTauri()) return realInvoke<Me>("get_me")
    return Promise.resolve(mockMe)
  },

  listContacts(): Promise<Contact[]> {
    if (isTauri()) return realInvoke<Contact[]>("list_contacts")
    return Promise.resolve([...mockState().contacts])
  },

  addContact(user_id: string, display_name: string, public_key_hex: string): Promise<void> {
    if (isTauri()) return realInvoke<void>("add_contact", { user_id, display_name, public_key_hex })
    mockState().contacts.push({ user_id, display_name })
    return Promise.resolve()
  },

  getHistory(contact_user_id: string, limit: number): Promise<HistoryItem[]> {
    if (isTauri()) return realInvoke<HistoryItem[]>("get_history", { contact_user_id, limit })
    return Promise.resolve(mockState().history[contact_user_id] ?? [])
  },

  sendMessage(contact_user_id: string, text: string): Promise<void> {
    if (isTauri()) return realInvoke<void>("send_message", { contact_user_id, text })
    const state = mockState()
    if (!state.history[contact_user_id]) state.history[contact_user_id] = []
    state.history[contact_user_id].push({ direction: "sent", text, sent_at: nowSec() })
    // Echo demo
    if (contact_user_id === state.contacts[2]?.user_id) {
      setTimeout(() => {
        state.history[contact_user_id].push({ direction: "received", text, sent_at: nowSec() + 1 })
        state.listeners.forEach((h) => h({ from_user_id: contact_user_id, text }))
      }, 600)
    }
    return Promise.resolve()
  },

  getMyCard(): Promise<string> {
    if (isTauri()) return realInvoke<string>("get_my_card")
    return Promise.resolve(JSON.stringify(mockMe))
  },

  lookupUser(user_id: string): Promise<{ user_id: string; public_key_hex: string }> {
    if (isTauri()) return realInvoke("lookup_user", { user_id })
    const contact = mockState().contacts.find((c) => c.user_id === user_id)
    if (!contact) return Promise.reject("User not found")
    return Promise.resolve({ user_id, public_key_hex: randomHex(64) })
  },

  updateRelays(relays: Relay[]): Promise<void> {
    if (isTauri()) return realInvoke<void>("update_relays", { relays })
    mockState().connected = true
    return Promise.resolve()
  },

  /// Сохраняет URL bootstrap-сервера и немедленно получает relay от него.
  /// После этого вызова relay подтягиваются автоматически при каждом запуске.
  setBootstrapUrl(url: string): Promise<void> {
    if (isTauri()) return realInvoke<void>("set_bootstrap_url", { url })
    mockState().bootstrapUrl = url
    mockState().connected = true // mock: считаем что сразу ок
    return Promise.resolve()
  },

  /// Возвращает сохранённый URL bootstrap-сервера (null если не задан).
  getBootstrapUrl(): Promise<string | null> {
    if (isTauri()) return realInvoke<string | null>("get_bootstrap_url")
    return Promise.resolve(mockState().bootstrapUrl)
  },

  /// Сбрасывает сохранённый URL bootstrap-сервера.
  clearBootstrapUrl(): Promise<void> {
    if (isTauri()) return realInvoke<void>("clear_bootstrap_url")
    mockState().bootstrapUrl = null
    return Promise.resolve()
  },
}

// Sample bootstrap response (for mock/dev preview only)
export const SAMPLE_BOOTSTRAP_URL = "http://your-friend-pc:8080"

export function onMessageReceived(handler: (payload: MessageReceived) => void): Promise<() => void> {
  return isTauri() ? realListen("message-received", handler) : mockListen("message-received", handler)
}

export const IS_MOCK = !isTauri()
