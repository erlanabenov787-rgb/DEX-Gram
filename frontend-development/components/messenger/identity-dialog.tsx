'use client'

import { useEffect, useRef, useState } from 'react'
import { Loader2, ShieldCheck } from 'lucide-react'
import { api, type Me } from '@/lib/tauri'
import { Copyable } from './copyable'
import { Modal } from './modal'

declare global {
  interface Window {
    QRCode?: new (el: HTMLElement, opts: Record<string, unknown>) => unknown
  }
}

const QR_CDN = 'https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js'

function loadQrLib(): Promise<void> {
  if (window.QRCode) return Promise.resolve()
  return new Promise((resolve, reject) => {
    const existing = document.querySelector<HTMLScriptElement>(`script[src="${QR_CDN}"]`)
    if (existing) {
      existing.addEventListener('load', () => resolve())
      existing.addEventListener('error', () => reject(new Error('failed to load QR library')))
      return
    }
    const s = document.createElement('script')
    s.src = QR_CDN
    s.async = true
    s.onload = () => resolve()
    s.onerror = () => reject(new Error('failed to load QR library'))
    document.head.appendChild(s)
  })
}

export function IdentityDialog({
  open,
  onClose,
  me,
}: {
  open: boolean
  onClose: () => void
  me: Me | null
}) {
  const qrRef = useRef<HTMLDivElement>(null)
  const [card, setCard] = useState<string | null>(null)
  const [status, setStatus] = useState<'idle' | 'loading' | 'ready' | 'error'>('idle')

  useEffect(() => {
    if (!open) return
    let cancelled = false
    setStatus('loading')

    ;(async () => {
      try {
        const cardStr = await api.getMyCard()
        if (cancelled) return
        setCard(cardStr)
        await loadQrLib()
        if (cancelled || !qrRef.current || !window.QRCode) return
        qrRef.current.innerHTML = ''
        new window.QRCode(qrRef.current, {
          text: cardStr,
          width: 220,
          height: 220,
          colorDark: '#0b0f0d',
          colorLight: '#ffffff',
          correctLevel: 1, // Medium
        })
        if (!cancelled) setStatus('ready')
      } catch {
        if (!cancelled) setStatus('error')
      }
    })()

    return () => {
      cancelled = true
    }
  }, [open])

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="My identity"
      description="Share this QR card so a contact can add you without typing anything."
    >
      <div className="flex flex-col items-center">
        <div className="relative flex size-[248px] items-center justify-center rounded-2xl bg-white p-3.5 shadow-inner ring-1 ring-border">
          <div ref={qrRef} className="[&_img]:rounded-md" aria-hidden={status !== 'ready'} />
          {status !== 'ready' ? (
            <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 rounded-2xl bg-white text-neutral-500">
              {status === 'error' ? (
                <p className="px-6 text-center text-sm">Couldn&apos;t render the QR code.</p>
              ) : (
                <Loader2 className="size-6 animate-spin" />
              )}
            </div>
          ) : null}
        </div>

        <div className="mt-5 w-full space-y-3">
          <div>
            <p className="mb-1 text-[11px] font-medium tracking-wide text-muted-foreground">USER ID</p>
            <Copyable
              value={me?.user_id ?? ''}
              full
              className="text-[13px] leading-relaxed"
            />
          </div>
          <div>
            <p className="mb-1 text-[11px] font-medium tracking-wide text-muted-foreground">
              PUBLIC KEY
            </p>
            <Copyable
              value={me?.public_key_hex ?? ''}
              full
              className="text-[13px] leading-relaxed"
            />
          </div>
        </div>

        <div className="mt-4 flex w-full items-center gap-2 rounded-xl bg-accent px-3 py-2.5 text-[13px] text-accent-foreground">
          <ShieldCheck className="size-4 shrink-0" />
          <span>Your keys live only on this device. Nothing is uploaded.</span>
        </div>
      </div>
    </Modal>
  )
}
