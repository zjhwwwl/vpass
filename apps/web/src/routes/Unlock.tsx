import { useState, type FormEvent } from 'react';
import { Button, ErrorText, KdfProgress, PasswordField, TextField } from '../components/ui.js';
import { errorMessage } from '../lib/api.js';
import { session, type PublicState } from '../state/session.js';

export function UnlockScreen({ st }: { st: PublicState }) {
  const [password, setPassword] = useState('');
  const [secretKey, setSecretKey] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await session.unlock(password, st.hasDeviceKey ? undefined : secretKey);
    } catch (err) {
      setError(errorMessage(err));
      setPassword('');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth">
      <form className="auth-card" onSubmit={submit}>
        <div className="brand">
          <img src="/icon.svg" alt="" width={36} height={36} />
          <span>已锁定</span>
        </div>
        {/* Hidden username helps password managers/browsers associate the field; never sent anywhere. */}
        <input type="email" name="email" autoComplete="username" value={st.bundle?.email ?? ''} readOnly hidden />
        <p className="muted">{st.bundle?.email}</p>
        {!st.online && <div className="callout">离线模式：从本机的密文缓存解锁，修改会在联网后同步。</div>}
        <PasswordField label="主密码" name="password" value={password} onChange={setPassword} autoComplete="current-password" autoFocus />
        {!st.hasDeviceKey && (
          <TextField label="Secret Key" value={secretKey} onChange={setSecretKey} mono placeholder="VP1-…" hint="这台设备上没有保存 Secret Key，请照应急卡输入。" />
        )}
        <ErrorText error={error} />
        {busy && <KdfProgress />}
        <Button kind="primary" type="submit" disabled={busy || !password}>
          解锁
        </Button>
        <div className="row spread">
          <Button kind="ghost" small onClick={() => void session.logout()}>
            退出登录
          </Button>
          <Button kind="ghost" small onClick={() => void session.logout(true)} title="退出并删除这台设备上保存的 Secret Key">
            退出并忘记此设备
          </Button>
        </div>
      </form>
    </div>
  );
}
