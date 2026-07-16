import { avatarGradient, initial } from '@/lib/messenger-utils'
import { cn } from '@/lib/utils'

export function Avatar({
  seed,
  name,
  className,
}: {
  seed: string
  name: string
  className?: string
}) {
  return (
    <div
      className={cn(
        'flex shrink-0 items-center justify-center rounded-full font-semibold text-white select-none',
        className,
      )}
      style={{ background: avatarGradient(seed) }}
      aria-hidden="true"
    >
      {initial(name)}
    </div>
  )
}
