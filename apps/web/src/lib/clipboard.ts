// Copy, then overwrite the clipboard with an empty string after N seconds (best effort: browsers may refuse
// when the page is not focused, and clipboard managers may already have a copy — the UI says so).
let timer: ReturnType<typeof setTimeout> | null = null;
let lastCopied: string | null = null;
const listeners = new Set<(secondsLeft: number | null) => void>();
let countdown: ReturnType<typeof setInterval> | null = null;

export function onClipboardCountdown(fn: (secondsLeft: number | null) => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

function notify(v: number | null) {
  for (const l of listeners) l(v);
}

export async function copySecret(value: string, seconds = 30): Promise<void> {
  await navigator.clipboard.writeText(value);
  lastCopied = value;
  if (timer) clearTimeout(timer);
  if (countdown) clearInterval(countdown);
  let left = seconds;
  notify(left);
  countdown = setInterval(() => {
    left -= 1;
    notify(left > 0 ? left : null);
    if (left <= 0 && countdown) clearInterval(countdown);
  }, 1000);
  timer = setTimeout(() => void clearClipboard(), seconds * 1000);
}

export async function clearClipboard(): Promise<void> {
  if (timer) clearTimeout(timer);
  if (countdown) clearInterval(countdown);
  timer = null;
  countdown = null;
  notify(null);
  if (lastCopied === null) return;
  lastCopied = null;
  try {
    await navigator.clipboard.writeText('');
  } catch {
    /* page not focused; nothing more we can do */
  }
}
