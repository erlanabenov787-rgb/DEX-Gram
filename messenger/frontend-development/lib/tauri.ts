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
          { direction: "received", text: "I echo everything you send me. try it.", sent_at: nowSec() - 120 },
        ],
      },
    }
  }
  return g.__messengerMock
}

function delay(ms: number) {
  return new Promise((r) => setTimeout(r, ms))
}

async function mockInvoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  const s = mockState()
  switch (cmd) {
    case "get_me":
      return mockMe as T
    case "get_my_card":
      return `${mockMe.user_id}:${mockMe.public_key_hex}` as T
    case "list_contacts":
      return [...s.contacts] as T
    case "add_contact": {
      const userId = args?.userId as string
      const displayName = args?.displayName as string
      if (!s.contacts.some((c) => c.user_id === userId)) {
        s.contacts.push({ user_id: userId, display_name: displayName })
        s.history[userId] = s.history[userId] ?? []
      }
      return undefined as T
    }
    case "get_history": {
      const id = args?.contactUserId as string
      return (s.history[id] ?? []) as T
    }
    case "send_message": {
      const id = args?.contactUserId as string
      const text = args?.text as string
      await delay(600)
      if (!s.connected) {
        throw "relay layer not connected — call update_relays first"
      }
      s.history[id] = s.history[id] ?? []
      s.history[id].push({ direction: "sent", text, sent_at: nowSec() })
      // The demo "Echo" contact bounces messages back so real-time updates
      // can be seen in the preview.
      if (id.startsWith("112233")) {
        await delay(900)
        s.history[id].push({ direction: "received", text, sent_at: nowSec() })
        s.listeners.forEach((fn) => fn({ from_user_id: id, text }))
      }
      return undefined as T
    }
    case "lookup_user": {
      const userId = args?.userId as string
      await delay(2200)
      if (userId.length < 8) throw "user not found on the network"
      return { user_id: userId, public_key_hex: randomHex(64) } as T
    }
    case "update_relays": {
      const relays = (args?.relays as Relay[]) ?? []
      await delay(1200)
      if (!Array.isArray(relays) || relays.length === 0) {
        throw "no relays provided — the bootstrap response was empty"
      }
      s.connected = true
      return undefined as T
    }
    default:
      throw `unknown command: ${cmd}`
  }
}

async function mockListen(
  _event: string,
  handler: (payload: MessageReceived) => void,
): Promise<() => void> {
  const s = mockState()
  s.listeners.add(handler)
  return () => {
    s.listeners.delete(handler)
  }
}

// ---------------------------------------------------------------------------
// Public API — identical shape regardless of environment
// ---------------------------------------------------------------------------

const call = <T>(cmd: string, args?: Record<string, unknown>): Promise<T> =>
  isTauri() ? realInvoke<T>(cmd, args) : mockInvoke<T>(cmd, args)

export const api = {
  getMe: () => call<Me>("get_me"),
  getMyCard: () => call<string>("get_my_card"),
  listContacts: () => call<Contact[]>("list_contacts"),
  addContact: (userId: string, displayName: string, publicKeyHex: string) =>
    call<void>("add_contact", { userId, displayName, publicKeyHex }),
  getHistory: (contactUserId: string, limit = 200) =>
    call<HistoryItem[]>("get_history", { contactUserId, limit }),
  sendMessage: (contactUserId: string, text: string) =>
    call<void>("send_message", { contactUserId, text }),
  lookupUser: (userId: string) => call<Me>("lookup_user", { userId }),
  updateRelays: (relays: Relay[]) => call<void>("update_relays", { relays }),
}

// Placeholder relay set. In production the relays come from the bootstrap
// server response, which the user pastes into the connection form (until the
// dedicated bootstrap client is wired up to fetch them automatically).
export const PLACEHOLDER_RELAYS: Relay[] = mockRelays

// A realistic example of what a bootstrap server hands back. Offered as a
// "paste sample" affordance so the connection flow can be exercised in the
// preview without a live bootstrap server.
export const SAMPLE_BOOTSTRAP_RESPONSE = JSON.stringify(
  {
    relays: [
      {
        peer_id: "12D3KooWQ8b7f2aEr4Jd9pLmN3xY6vHk1sT7wZ2cB5nD8gF0aQ",
        multiaddr: "/onion3/v1x2y3z4a5b6c7d8e9f0g1h2i3j4k5l6:1042",
        onion_public_key: "9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d",
      },
      {
        peer_id: "12D3KooWLmN3xY6vHk1sT7wZ2cB5nD8gF0aQ8b7f2aEr4Jd9pL",
        multiaddr: "/onion3/q7w8e9r0t1y2u3i4o5p6a7s8d9f0g1h2:1042",
        onion_public_key: "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
      },
    ],
  },
  null,
  2,
)

// Parses the raw text a user pastes from their bootstrap server into a typed
// relay list. Accepts either a bare array or an object with a `relays` key.
// Throws a plain-string error (matching the backend convention) on bad input.
export function parseBootstrapResponse(raw: string): Relay[] {
  const trimmed = raw.trim()
  if (!trimmed) throw "Paste the bootstrap server response first."

  let parsed: unknown
  try {
    parsed = JSON.parse(trimmed)
  } catch {
    throw "That isn't valid JSON. Paste the raw response from your bootstrap server."
  }

  const arr = Array.isArray(parsed)
    ? parsed
    : (parsed as { relays?: unknown })?.relays

  if (!Array.isArray(arr) || arr.length === 0) {
    throw "Expected a non-empty list of relays (an array, or an object with a \"relays\" array)."
  }

  return arr.map((item, i) => {
    const r = item as Record<string, unknown>
    const peer_id = r?.peer_id
    const multiaddr = r?.multiaddr
    const onion_public_key = r?.onion_public_key
    if (
      typeof peer_id !== "string" ||
      typeof multiaddr !== "string" ||
      typeof onion_public_key !== "string" ||
      !peer_id ||
      !multiaddr ||
      !onion_public_key
    ) {
      throw `Relay #${i + 1} is missing "peer_id", "multiaddr", or "onion_public_key".`
    }
    return { peer_id, multiaddr, onion_public_key }
  })
}

export function onMessageReceived(handler: (payload: MessageReceived) => void): Promise<() => void> {
  return isTauri() ? realListen("message-received", handler) : mockListen("message-received", handler)
}

export const IS_MOCK = !isTauri()
