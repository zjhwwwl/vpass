import { useEffect, useState, type FormEvent, type ReactNode } from 'react';
import type { EncryptedExport } from '@vpass/crypto';
import type { SessionInfo } from '@vpass/shared';
import { EmergencyKit } from '../components/EmergencyKit.js';
import { Button, ErrorText, KdfProgress, Modal, PasswordField, QrCode, StrengthMeter, TextField, passwordScore } from '../components/ui.js';
import { api, errorMessage } from '../lib/api.js';
import { detectFormat, exportCsv, importItems } from '../lib/csv.js';
import { downloadText, readFileText } from '../lib/download.js';
import { kdf } from '../lib/kdfWorker.js';
import { normalizeItem, type Item } from '../lib/item.js';
import { session, type PublicState } from '../state/session.js';
import { Fingerprint } from './Sharing.js';

type Section = 'security' | 'devices' | 'data' | 'prefs';

export function Settings({ st, onClose }: { st: PublicState; onClose: () => void }) {
  const [tab, setTab] = useState<Section>('security');
  return (
    <Modal title="设置" onClose={onClose} wide>
      <div className="tabs small">
        {(
          [
            ['security', '账号安全'],
            ['devices', '设备与二次验证'],
            ['data', '导入导出'],
            ['prefs', '偏好'],
          ] as const
        ).map(([k, l]) => (
          <button key={k} className={tab === k ? 'active' : ''} onClick={() => setTab(k)}>
            {l}
          </button>
        ))}
      </div>
      {tab === 'security' && <SecuritySettings st={st} />}
      {tab === 'devices' && <DeviceSettings st={st} />}
      {tab === 'data' && <DataSettings />}
      {tab === 'prefs' && <Prefs st={st} />}
    </Modal>
  );
}

function Card({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="card">
      <h3>{title}</h3>
      {children}
    </section>
  );
}

function SecuritySettings({ st }: { st: PublicState }) {
  return (
    <div className="settings">
      <Card title="我的公钥指纹">
        <p className="hint">朋友共享保管库给你时，要和你核对这一串。</p>
        {st.bundle && <Fingerprint publicKey={st.bundle.publicKey} />}
      </Card>
      <Card title="Secret Key 二维码（新设备登录用）">
        <ShowSecretKey />
      </Card>
      <Card title="修改主密码">
        <ChangePassword />
      </Card>
      <Card title="重新生成恢复码">
        <RegenRecovery email={st.bundle?.email ?? ''} />
      </Card>
      <Card title="轮换 Secret Key">
        <RotateSecretKey email={st.bundle?.email ?? ''} />
      </Card>
      {st.bundle?.isAdmin && (
        <Card title="邀请码（管理员）">
          <Invite />
        </Card>
      )}
    </div>
  );
}

function ShowSecretKey() {
  const [sk, setSk] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => () => setSk(null), []);
  if (!sk)
    return (
      <>
        <p className="hint">在新手机上用系统相机扫码，复制得到的文字，粘贴到登录页的 Secret Key 输入框。显示时注意身后有没有人。</p>
        <Button onClick={() => session.secretKeyDisplay().then(setSk, (e) => setError(errorMessage(e)))}>显示二维码</Button>
        <ErrorText error={error} />
      </>
    );
  return (
    <div className="qr-box">
      <QrCode text={sk} />
      <code className="mono">{sk}</code>
      <Button onClick={() => setSk(null)}>隐藏</Button>
    </div>
  );
}

function ChangePassword() {
  const [old, setOld] = useState('');
  const [pw, setPw] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setMsg(null);
    if (pw !== confirm) return setError('两次输入不一致');
    if ((await passwordScore(pw)) < 3) return setError('新主密码强度不够（需要 zxcvbn ≥ 3）');
    setBusy(true);
    try {
      await session.changePassword(old, pw);
      setMsg('主密码已修改，其他设备已全部登出。');
      setOld('');
      setPw('');
      setConfirm('');
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }
  return (
    <form onSubmit={submit}>
      <input type="text" autoComplete="username" value={session.getSnapshot().bundle?.email ?? ''} readOnly hidden />
      <PasswordField label="当前主密码" value={old} onChange={setOld} autoComplete="current-password" />
      <PasswordField label="新主密码" value={pw} onChange={setPw} autoComplete="new-password" />
      <StrengthMeter password={pw} />
      <PasswordField label="再输入一次" value={confirm} onChange={setConfirm} autoComplete="new-password" />
      <ErrorText error={error} />
      {msg && <div className="ok">{msg}</div>}
      {busy && <KdfProgress />}
      <Button kind="primary" type="submit" disabled={busy || !old || !pw}>
        修改
      </Button>
    </form>
  );
}

function RegenRecovery({ email }: { email: string }) {
  const [pw, setPw] = useState('');
  const [code, setCode] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  if (code)
    return (
      <div>
        <div className="callout">新恢复码只显示这一次，旧恢复码已作废。</div>
        <code className="mono big">{code}</code>
        <p className="hint">{email}</p>
        <Button onClick={() => setCode(null)}>我已抄下</Button>
      </div>
    );
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        setBusy(true);
        setError(null);
        session.regenerateRecoveryCode(pw).then(
          (c) => (setCode(c), setPw(''), setBusy(false)),
          (err) => (setError(errorMessage(err)), setBusy(false)),
        );
      }}
    >
      <PasswordField label="主密码" value={pw} onChange={setPw} autoComplete="current-password" />
      <ErrorText error={error} />
      {busy && <KdfProgress />}
      <Button type="submit" disabled={busy || !pw}>
        生成新恢复码
      </Button>
    </form>
  );
}

function RotateSecretKey({ email }: { email: string }) {
  const [pw, setPw] = useState('');
  const [sk, setSk] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  if (sk)
    return (
      <div>
        <div className="callout">Secret Key 已轮换，其他设备已登出，需要用新的 Secret Key 重新登录。请打印新应急卡。</div>
        <EmergencyKit email={email} secretKey={sk} recoveryCode={null} />
      </div>
    );
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        if (!confirm('轮换后所有其他设备都要用新的 Secret Key 重新登录。继续？')) return;
        setBusy(true);
        setError(null);
        session.rotateSecretKey(pw).then(
          (k) => (setSk(k), setBusy(false)),
          (err) => (setError(errorMessage(err)), setBusy(false)),
        );
      }}
    >
      <p className="hint">设备丢失或怀疑 Secret Key 泄露时使用。</p>
      <PasswordField label="主密码" value={pw} onChange={setPw} autoComplete="current-password" />
      <ErrorText error={error} />
      {busy && <KdfProgress />}
      <Button kind="danger" type="submit" disabled={busy || !pw}>
        轮换 Secret Key
      </Button>
    </form>
  );
}

function Invite() {
  const [code, setCode] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  return (
    <div>
      {code ? (
        <>
          <code className="mono big">{code}</code>
          <p className="hint">只显示一次，7 天内有效，只能用一次。</p>
        </>
      ) : (
        <Button onClick={() => api.createInvite().then((r) => setCode(r.code), (e) => setError(errorMessage(e)))}>生成邀请码</Button>
      )}
      <ErrorText error={error} />
    </div>
  );
}

function DeviceSettings({ st }: { st: PublicState }) {
  const [sessions, setSessions] = useState<SessionInfo[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const reload = () => api.sessions().then((r) => setSessions(r.sessions), (e) => setError(errorMessage(e)));
  useEffect(() => {
    void reload();
  }, []);
  return (
    <div className="settings">
      <Card title="登录设备">
        <ErrorText error={error} />
        <ul className="plain">
          {sessions?.map((s) => (
            <li key={s.id} className="row spread">
              <span>
                {s.deviceLabel ?? '未知设备'} {s.current && <span className="badge">当前</span>}
                <br />
                <span className="muted small">最近活动 {new Date(s.lastSeenAt).toLocaleString()}</span>
              </span>
              {!s.current && (
                <Button small kind="danger" onClick={() => api.revokeSession(s.id).then(reload, (e) => setError(errorMessage(e)))}>
                  踢下线
                </Button>
              )}
            </li>
          ))}
        </ul>
      </Card>
      <Card title="登录二次验证（TOTP）">
        <TwoFactor enabled={!!st.bundle?.totpEnabled} />
      </Card>
    </div>
  );
}

function TwoFactor({ enabled }: { enabled: boolean }) {
  const [setup, setSetup] = useState<{ secret: string; uri: string } | null>(null);
  const [code, setCode] = useState('');
  const [pw, setPw] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const refresh = async () => session.setBundle(await api.me());

  if (enabled)
    return (
      <form
        onSubmit={(e) => {
          e.preventDefault();
          setBusy(true);
          session
            .currentAuthHash(pw)
            .then((h) => api.totpDisable(h))
            .then(refresh)
            .catch((err) => setError(errorMessage(err)))
            .finally(() => setBusy(false));
        }}
      >
        <p className="ok">已开启。登录新设备时需要验证码。</p>
        <PasswordField label="输入主密码以关闭" value={pw} onChange={setPw} />
        <ErrorText error={error} />
        <Button kind="danger" type="submit" disabled={busy || !pw}>
          关闭二次验证
        </Button>
      </form>
    );
  if (!setup)
    return (
      <>
        <p className="hint">开启后，登录时除了主密码还需要验证器 App 里的 6 位码。</p>
        <Button onClick={() => api.totpSetup().then(setSetup, (e) => setError(errorMessage(e)))}>开始设置</Button>
        <ErrorText error={error} />
      </>
    );
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        setBusy(true);
        session
          .currentAuthHash(pw)
          .then((h) => api.totpEnable(code, h))
          .then(refresh)
          .catch((err) => setError(errorMessage(err)))
          .finally(() => setBusy(false));
      }}
    >
      <QrCode text={setup.uri} size={180} />
      <code className="mono">{setup.secret}</code>
      <TextField label="验证器显示的 6 位码" value={code} onChange={setCode} autoComplete="one-time-code" />
      <PasswordField label="主密码（确认是你本人）" value={pw} onChange={setPw} />
      <ErrorText error={error} />
      {busy && <KdfProgress />}
      <Button kind="primary" type="submit" disabled={code.length !== 6 || !pw || busy}>
        开启
      </Button>
    </form>
  );
}

function DataSettings() {
  const [expPw, setExpPw] = useState('');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [plainConfirm, setPlainConfirm] = useState(false);
  const [importFile, setImportFile] = useState<{ name: string; text: string } | null>(null);
  const [importPw, setImportPw] = useState('');
  const vaults = session.vaults().filter((v) => v.role !== 'viewer');
  const [target, setTarget] = useState(session.personalVaultId() ?? '');

  const allItems = () => session.items().filter((i) => i.item.type !== 'contact');

  async function exportEncrypted() {
    if ((await passwordScore(expPw)) < 3) return setError('导出密码强度不够（zxcvbn ≥ 3）');
    setBusy(true);
    setError(null);
    try {
      const file = await kdf.encryptExport(expPw, { exportedAt: new Date().toISOString(), items: allItems().map((i) => i.item) });
      downloadText(`vpass-${new Date().toISOString().slice(0, 10)}.json`, JSON.stringify(file, null, 2), 'application/json');
      setMsg('已导出加密备份。');
      setExpPw('');
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  async function runImport() {
    if (!importFile || !target) return;
    setBusy(true);
    setError(null);
    setMsg(null);
    try {
      let items: Item[];
      const t = importFile.text.trimStart();
      if (t.startsWith('{') && t.includes('"vpass-export"')) {
        const data = await kdf.decryptExport<{ items: unknown[] }>(importPw, JSON.parse(t) as EncryptedExport);
        items = data.items.map(normalizeItem);
      } else {
        const fmt = detectFormat(importFile.text);
        if (!fmt) throw new Error('unknown_format');
        items = importItems(importFile.text, fmt);
      }
      let n = 0;
      for (const it of items) {
        await session.saveItem(target, null, it);
        n++;
      }
      setMsg(`已导入 ${n} 个条目。导入文件是明文，请立即删除它。`);
      setImportFile(null);
    } catch (e) {
      setError(e instanceof Error && e.message === 'unknown_format' ? '无法识别文件格式' : e instanceof Error && e.message === 'bitwarden_encrypted' ? '不支持 Bitwarden 加密导出，请导出未加密的 JSON 或 CSV' : errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="settings">
      <Card title="加密导出（推荐，用于自己备份）">
        <PasswordField label="导出密码（与主密码不同）" value={expPw} onChange={setExpPw} autoComplete="new-password" />
        <StrengthMeter password={expPw} />
        <Button kind="primary" disabled={busy || !expPw} onClick={() => void exportEncrypted()}>
          导出加密 JSON
        </Button>
        {busy && <KdfProgress />}
      </Card>
      <Card title="明文 CSV 导出">
        <div className="callout danger">明文文件里所有密码都没有加密。任何拿到文件的人都能看到全部密码。用完立即删除。</div>
        <label className="check">
          <input type="checkbox" checked={plainConfirm} onChange={(e) => setPlainConfirm(e.target.checked)} /> 我明白风险
        </label>
        <Button
          kind="danger"
          disabled={!plainConfirm}
          onClick={() => {
            if (!confirm('再次确认：导出未加密的明文 CSV？')) return;
            downloadText('vpass-明文.csv', exportCsv(allItems().map((i) => i.item)), 'text/csv;charset=utf-8');
            setPlainConfirm(false);
          }}
        >
          导出明文 CSV
        </Button>
      </Card>
      <Card title="导入">
        <p className="hint">支持 Bitwarden（JSON/CSV）、1Password CSV、Chrome CSV、VPass 加密导出。文件只在浏览器里解析。</p>
        <input
          type="file"
          accept=".csv,.json,text/csv,application/json"
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) void readFileText(f).then((text) => setImportFile({ name: f.name, text }));
          }}
        />
        {importFile && (
          <>
            {importFile.text.includes('"vpass-export"') && <PasswordField label="导出密码" value={importPw} onChange={setImportPw} autoComplete="off" />}
            <label className="check">
              导入到
              <select value={target} onChange={(e) => setTarget(e.target.value)}>
                {vaults.map((v) => (
                  <option key={v.id} value={v.id}>
                    {v.name}
                  </option>
                ))}
              </select>
            </label>
            <Button kind="primary" disabled={busy} onClick={() => void runImport()}>
              导入 {importFile.name}
            </Button>
          </>
        )}
      </Card>
      <ErrorText error={error} />
      {msg && <div className="ok">{msg}</div>}
    </div>
  );
}

function Prefs({ st }: { st: PublicState }) {
  const s = st.settings;
  return (
    <div className="settings">
      <Card title="自动锁定">
        <label className="check">
          无操作
          <select value={s.autoLockMinutes} onChange={(e) => void session.patchSettings({ autoLockMinutes: Number(e.target.value) })}>
            {[1, 5, 10, 15, 30, 60].map((m) => (
              <option key={m} value={m}>
                {m} 分钟
              </option>
            ))}
          </select>
          后锁定
        </label>
        <label className="check">
          页面隐藏
          <select value={s.hiddenLockMinutes} onChange={(e) => void session.patchSettings({ hiddenLockMinutes: Number(e.target.value) })}>
            {[0, 1, 5, 10, 30].map((m) => (
              <option key={m} value={m}>
                {m === 0 ? '立即' : `${m} 分钟`}
              </option>
            ))}
          </select>
          后锁定
        </label>
        <p className="hint">快捷键 Alt+L 立即锁定。</p>
      </Card>
      <Card title="剪贴板">
        <label className="check">
          复制后
          <select value={s.clipboardSeconds} onChange={(e) => void session.patchSettings({ clipboardSeconds: Number(e.target.value) })}>
            {[10, 20, 30, 60, 90].map((m) => (
              <option key={m} value={m}>
                {m} 秒
              </option>
            ))}
          </select>
          清空（尽力而为）
        </label>
      </Card>
      <Card title="离线缓存">
        <label className="check">
          <input type="checkbox" checked={s.offlineCache} onChange={(e) => void session.patchSettings({ offlineCache: e.target.checked })} />
          在本机 IndexedDB 保存密文副本，断网时也能解锁查看
        </label>
      </Card>
    </div>
  );
}
