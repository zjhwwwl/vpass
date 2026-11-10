import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { parseSecretKey, type Registration } from '@vpass/crypto';
import { Button, ErrorText, KdfProgress, PasswordField, StrengthMeter, TextField, passwordScore } from '../components/ui.js';
import { EmergencyKit } from '../components/EmergencyKit.js';
import { errorMessage } from '../lib/api.js';
import { kdf } from '../lib/kdfWorker.js';
import { session } from '../state/session.js';

type Tab = 'login' | 'register' | 'recover';

export function AuthScreen() {
  const [tab, setTab] = useState<Tab>(() => (location.hash === '#register' ? 'register' : 'login'));
  return (
    <div className="auth">
      <div className="auth-card">
        <div className="brand">
          <img src="/icon.svg" alt="" width={36} height={36} />
          <span>VPass</span>
        </div>
        <div className="tabs" role="tablist">
          {(['login', 'register', 'recover'] as const).map((t) => (
            <button key={t} role="tab" aria-selected={tab === t} className={tab === t ? 'active' : ''} onClick={() => setTab(t)}>
              {t === 'login' ? '登录' : t === 'register' ? '注册' : '用恢复码找回'}
            </button>
          ))}
        </div>
        {tab === 'login' && <Login />}
        {tab === 'register' && <Register />}
        {tab === 'recover' && <Recover />}
      </div>
      <p className="auth-foot">只通过书签或主屏幕图标打开本站，不要点击邮件里的链接。</p>
    </div>
  );
}

function Login() {
  const [email, setEmail] = useState(session.getSnapshot().settings.lastEmail ?? '');
  const [password, setPassword] = useState('');
  const [secretKey, setSecretKey] = useState('');
  const [totp, setTotp] = useState('');
  const [needTotp, setNeedTotp] = useState(false);
  const [known, setKnown] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const t = setTimeout(() => {
      if (email.includes('@')) void session.deviceKnows(email).then((k) => alive && setKnown(k));
      else setKnown(null);
    }, 200);
    return () => {
      alive = false;
      clearTimeout(t);
    };
  }, [email]);

  const skError = useMemo(() => {
    if (known !== false || !secretKey) return null;
    try {
      parseSecretKey(secretKey);
      return null;
    } catch (e) {
      return errorMessage(e);
    }
  }, [secretKey, known]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (skError) return setError(skError);
    setBusy(true);
    try {
      const r = await session.login(email.trim(), password, known === false ? secretKey : null, needTotp ? totp : undefined);
      if (r === 'totp') setNeedTotp(true);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit}>
      <TextField label="邮箱" name="email" type="email" value={email} onChange={setEmail} autoComplete="username" autoFocus={!email} required />
      <PasswordField label="主密码" name="password" value={password} onChange={setPassword} autoComplete="current-password" autoFocus={!!email} />
      {known === false && (
        <TextField
          label="Secret Key（这台设备第一次登录）"
          value={secretKey}
          onChange={setSecretKey}
          placeholder="VP1-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XX"
          mono
          hint={skError ?? '照应急卡输入；或在已登录设备的“设置 → Secret Key 二维码”用手机相机扫码后粘贴。'}
        />
      )}
      {needTotp && <TextField label="二次验证码" value={totp} onChange={setTotp} autoComplete="one-time-code" placeholder="6 位数字" autoFocus />}
      <ErrorText error={error} />
      {busy && <KdfProgress />}
      <Button kind="primary" type="submit" disabled={busy || !email || !password}>
        {busy ? '正在登录…' : '登录'}
      </Button>
    </form>
  );
}

function Register() {
  const [invite, setInvite] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [reg, setReg] = useState<Registration | null>(null);
  const [printed, setPrinted] = useState(false);
  const [group, setGroup] = useState(0);
  const [check, setCheck] = useState('');

  async function prepare(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (password !== confirm) return setError('两次输入的主密码不一致');
    if ((await passwordScore(password, [email])) < 3) return setError('主密码强度不够（需要 zxcvbn ≥ 3）。试试 4 个以上随机单词。');
    setBusy(true);
    try {
      const r = await kdf.createAccount(email.trim().toLowerCase(), password);
      setReg(r);
      const pick = new Uint32Array(1);
      crypto.getRandomValues(pick);
      setGroup(pick[0]! % 8);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function finish(e: FormEvent) {
    e.preventDefault();
    if (!reg) return;
    const expected = reg.recoveryCode.split('-')[group]!;
    if (check.trim().toUpperCase() !== expected) return setError(`恢复码第 ${group + 1} 组不对，请对照应急卡再输入一次`);
    setBusy(true);
    setError(null);
    try {
      await session.register(invite.trim(), reg);
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }

  if (reg) {
    return (
      <form onSubmit={finish}>
        <div className="callout">
          <strong>保存你的应急卡。</strong>Secret Key 不会上传服务器；新设备登录需要它。恢复码只显示这一次，是忘记主密码时唯一的救命稻草。
        </div>
        <EmergencyKit email={reg.payload.email} secretKey={reg.secretKeyDisplay} recoveryCode={reg.recoveryCode} onPrinted={() => setPrinted(true)} />
        {printed && (
          <TextField
            label={`确认已保存：请输入恢复码的第 ${group + 1} 组（4 个字符）`}
            value={check}
            onChange={setCheck}
            mono
            autoFocus
          />
        )}
        <ErrorText error={error} />
        <Button kind="primary" type="submit" disabled={!printed || check.length < 4 || busy}>
          {busy ? '正在创建账号…' : '完成注册'}
        </Button>
      </form>
    );
  }

  return (
    <form onSubmit={prepare}>
      <TextField label="邀请码" value={invite} onChange={setInvite} mono placeholder="VPI-XXXX-XXXX-XXXX-XXXX" required />
      <TextField label="邮箱" type="email" value={email} onChange={setEmail} autoComplete="username" required />
      <PasswordField label="主密码" value={password} onChange={setPassword} autoComplete="new-password" hint="主密码只在你的浏览器里使用，服务器永远看不到。" />
      <StrengthMeter password={password} userInputs={[email]} />
      <PasswordField label="再输入一次" value={confirm} onChange={setConfirm} autoComplete="new-password" />
      <ErrorText error={error} />
      {busy && <KdfProgress label="正在生成密钥…" />}
      <Button kind="primary" type="submit" disabled={busy || !invite || !email || !password}>
        下一步：生成应急卡
      </Button>
    </form>
  );
}

function Recover() {
  const [email, setEmail] = useState('');
  const [code, setCode] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [opened, setOpened] = useState<Awaited<ReturnType<typeof session.recoverOpen>> | null>(null);
  const [kit, setKit] = useState<{ secretKey: string; recoveryCode: string; enter: () => Promise<void> } | null>(null);

  async function step1(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      setOpened(await session.recoverOpen(email.trim(), code));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function step2(e: FormEvent) {
    e.preventDefault();
    if (!opened) return;
    if (password !== confirm) return setError('两次输入的主密码不一致');
    if ((await passwordScore(password, [email])) < 3) return setError('主密码强度不够（需要 zxcvbn ≥ 3）');
    setBusy(true);
    setError(null);
    try {
      // Show the new kit before the session switches to the vault view.
      const res = await session.recoverFinish(email.trim(), opened, password);
      setKit(res);
    } catch (err) {
      setError(errorMessage(err));
      setBusy(false);
    }
  }

  if (kit)
    return (
      <div>
        <div className="callout">账号已重置，其他设备都已登出。请保存新的应急卡——旧的 Secret Key 和恢复码已经作废。</div>
        <EmergencyKit email={email} secretKey={kit.secretKey} recoveryCode={kit.recoveryCode} />
        <Button kind="primary" onClick={() => void kit.enter()}>
          我已保存，进入保管库
        </Button>
      </div>
    );

  if (opened) {
    return (
      <form onSubmit={step2}>
        <div className="callout">恢复码正确。设置新的主密码；同时会生成新的 Secret Key 和新的恢复码，所有设备都会被登出。</div>
        <PasswordField label="新主密码" value={password} onChange={setPassword} autoComplete="new-password" />
        <StrengthMeter password={password} userInputs={[email]} />
        <PasswordField label="再输入一次" value={confirm} onChange={setConfirm} autoComplete="new-password" />
        <ErrorText error={error} />
        {busy && <KdfProgress />}
        <Button kind="primary" type="submit" disabled={busy || !password}>
          重置并生成新应急卡
        </Button>
      </form>
    );
  }

  return (
    <form onSubmit={step1}>
      <TextField label="邮箱" type="email" value={email} onChange={setEmail} autoComplete="username" required />
      <TextField label="恢复码" value={code} onChange={setCode} mono placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX" required />
      <ErrorText error={error} />
      <Button kind="primary" type="submit" disabled={busy || !email || !code}>
        验证恢复码
      </Button>
    </form>
  );
}
