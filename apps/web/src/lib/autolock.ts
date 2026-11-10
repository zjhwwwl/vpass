// Auto-lock: idle for N minutes, or page hidden for M minutes. Alt+L locks immediately.
import { clearClipboard } from './clipboard.js';
import { session } from '../state/session.js';

let lastActivity = Date.now();
let hiddenSince: number | null = null;
let started = false;

function bump() {
  lastActivity = Date.now();
}

export function lockNow(): void {
  session.lock();
  void clearClipboard();
}

export function startAutoLock(): void {
  if (started) return;
  started = true;
  for (const ev of ['pointerdown', 'keydown', 'wheel', 'touchstart']) window.addEventListener(ev, bump, { passive: true });
  document.addEventListener('visibilitychange', () => {
    hiddenSince = document.hidden ? Date.now() : null;
    if (!document.hidden) check();
  });
  window.addEventListener('keydown', (e) => {
    if (e.altKey && !e.ctrlKey && !e.metaKey && (e.key === 'l' || e.key === 'L')) {
      e.preventDefault();
      lockNow();
    }
  });
  setInterval(check, 5000);
}

function check() {
  const st = session.getSnapshot();
  if (st.status !== 'unlocked') return;
  const now = Date.now();
  const idleMs = st.settings.autoLockMinutes * 60_000;
  const hiddenMs = st.settings.hiddenLockMinutes * 60_000;
  if (now - lastActivity >= idleMs || (hiddenSince !== null && now - hiddenSince >= hiddenMs)) lockNow();
}
