import { useEffect, useSyncExternalStore } from 'react';
import { session } from './state/session.js';
import { AuthScreen } from './routes/Auth.js';
import { UnlockScreen } from './routes/Unlock.js';
import { VaultApp } from './routes/VaultApp.js';
import { startAutoLock } from './lib/autolock.js';
import { UpdateBanner } from './components/UpdateBanner.js';

export function App() {
  const st = useSyncExternalStore(session.subscribe, session.getSnapshot);
  useEffect(() => {
    startAutoLock();
    void session.boot();
  }, []);
  return (
    <>
      <UpdateBanner />
      {st.status === 'booting' ? (
        <div className="auth">
          <div className="muted">正在加载…</div>
        </div>
      ) : st.status === 'loggedOut' ? (
        <AuthScreen />
      ) : st.status === 'locked' ? (
        <UnlockScreen st={st} />
      ) : (
        <VaultApp st={st} />
      )}
    </>
  );
}
