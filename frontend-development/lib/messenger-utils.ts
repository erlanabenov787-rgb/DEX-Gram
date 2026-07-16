// Small presentation helpers shared across the messenger UI.

export function truncateId(id: string, head = 6, tail = 6): string {
  if (id.length <= head + tail + 1) return id
  return `${id.slice(0, head)}…${id.slice(-tail)}`
}

export function initial(name: string): string {
  const trimmed = name.trim()
  return trimmed ? trimmed.slice(0, 1).toUpperCase() : "?"
}

// Deterministic gradient per contact so avatars are stable and colorful
// without storing anything.
const AVATAR_PAIRS: [string, string][] = [
  ["#0ea5a0", "#22d3b8"],
  ["#2563eb", "#60a5fa"],
  ["#d97706", "#f59e0b"],
  ["#059669", "#34d399"],
  ["#dc2626", "#f87171"],
  ["#0891b2", "#22d3ee"],
]

export function avatarGradient(seed: string): string {
  let h = 0
  for (let i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) >>> 0
  const [c1, c2] = AVATAR_PAIRS[h % AVATAR_PAIRS.length]
  return `linear-gradient(135deg, ${c1}, ${c2})`
}

export function formatTime(unixSec: number): string {
  return new Date(unixSec * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
}

export function formatDayLabel(unixSec: number): string {
  const d = new Date(unixSec * 1000)
  const today = new Date()
  const yesterday = new Date()
  yesterday.setDate(today.getDate() - 1)
  const sameDay = (a: Date, b: Date) =>
    a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate()
  if (sameDay(d, today)) return "Today"
  if (sameDay(d, yesterday)) return "Yesterday"
  return d.toLocaleDateString([], { month: "short", day: "numeric" })
}

export function dayKey(unixSec: number): string {
  const d = new Date(unixSec * 1000)
  return `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`
}
