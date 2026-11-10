import { useEffect, useState } from 'react';
import { fingerprint, fromB64u } from '@vpass/crypto';
import type { MemberDto } from '@vpass/shared';
import { Button, ErrorText, Modal, TextField } from '../components/ui.js';
import { api, errorMessage } from '../lib/api.js';
import { emptyItem } from '../lib/item.js';
import { session, type VaultView } from '../state/session.js';

/** Verified contacts live as encrypted `contact` items in the personal vault (section 8). */
function verifiedContact(userId: string) {
  return session.items(session.personalVaultId() ?? undefined).find((it) => it.item.type === 'contact' && it.item.contact?.userId === userId);
}

export function useFingerprint(publicKeyB64: string | null | undefined): string | null {
  const [fp, setFp] = useState<string | null>(null);
  useEffect(() => {
    if (!publicKeyB64) return;
    let alive = true;
    void fingerprint(fromB64u(publicKeyB64)).then((f) => alive && setFp(f));
    return () => {
      alive = false;
    };
  }, [publicKeyB64]);
  return fp;
}

export function Fingerprint({ publicKey }: { publicKey: string }) {
  const fp = useFingerprint(publicKey);
  return <code className="fingerprint">{fp ?? '…'}</code>;
}

type Trust = 'verified' | 'mismatch' | 'unverified';
function trustOf(m: { userId: string; publicKey: string }): Trust {
  const c = verifiedContact(m.userId);
  if (!c) return 'unverified';
  return c.item.contact!.publicKey === m.publicKey ? 'verified' : 'mismatch';
}

export function VaultMembers({ vault, onClose }: { vault: VaultView; onClose: () => void }) {
  const [members, setMembers] = useState<MemberDto[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);
  const [busy, setBusy] = useState(false);
  const isOwner = vault.role === 'owner';
  const me = session.userId();

  const reload = () => session.members(vault.id).then(setMembers, (e) => setError(errorMessage(e)));
  useEffect(() => {
    void reload();
  }, [vault.id]); // eslint-disable-line react-hooks/exhaustive-deps

  async function changeRole(m: MemberDto, role: 'editor' | 'viewer') {
    if (trustOf(m) !== 'verified') return setError('该成员的公钥未核验或与核验记录不一致，已阻止操作。');
    setBusy(true);
    try {
      await session.putMember(vault.id, m.userId, m.publicKey, role);
      await reload();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  async function remove(m: MemberDto) {
    if (!members) return;
    const keep = new Map<string, string>();
    for (const x of members) {
      if (x.userId === m.userId) continue;
      if (x.userId === me) {
        keep.set(x.userId, session.publicKey()!); // our own key from the login bundle, not the member list
        continue;
      }
      if (trustOf(x) !== 'verified') return setError(`成员 ${x.email} 的公钥未核验，无法为其重新封装新密钥。请先核验。`);
      keep.set(x.userId, verifiedContact(x.userId)!.item.contact!.publicKey);
    }
    if (!confirm(`移除 ${m.email}？\n\n保管库密钥会被轮换，库内所有条目重新加密。\n注意：对方可能已经记下了旧密码，重要账号请去对应网站修改密码。`)) return;
    setBusy(true);
    setError(null);
    try {
      await session.rotateVault(vault.id, keep);
      await reload();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal title={`成员 · ${vault.name}`} onClose={onClose} wide>
      <ErrorText error={error} />
      {!members ? (
        <p className="muted">加载中…</p>
      ) : (
        <table className="members">
          <thead>
            <tr>
              <th>成员</th>
              <th>角色</th>
              <th>公钥指纹</th>
              {isOwner && <th />}
            </tr>
          </thead>
          <tbody>
            {members.map((m) => {
              const t = m.userId === me ? 'verified' : trustOf(m);
              return (
                <tr key={m.userId} className={t === 'mismatch' ? 'danger-row' : ''}>
                  <td>
                    {m.email}
                    {m.userId === me && <span className="badge">我</span>}
                    {t === 'unverified' && <span className="badge warn">未核验</span>}
                    {t === 'mismatch' && <span className="badge danger">公钥已变化！</span>}
                  </td>
                  <td>
                    {isOwner && m.role !== 'owner' ? (
                      <select value={m.role} disabled={busy} onChange={(e) => void changeRole(m, e.target.value as 'editor' | 'viewer')}>
                        <option value="editor">可编辑</option>
                        <option value="viewer">只读</option>
                      </select>
                    ) : (
                      { owner: '所有者', editor: '可编辑', viewer: '只读' }[m.role]
                    )}
                  </td>
                  <td>
                    <Fingerprint publicKey={m.publicKey} />
                  </td>
                  {isOwner && (
                    <td>
                      {m.role !== 'owner' && (
                        <Button small kind="danger" disabled={busy} onClick={() => void remove(m)}>
                          移除
                        </Button>
                      )}
                    </td>
                  )}
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
      {members?.some((m) => m.userId !== me && trustOf(m) === 'mismatch') && (
        <div className="callout danger">
          服务器返回的某个成员公钥与你核验时记录的不一致。可能是对方重置了账号，也可能是服务器被篡改。在当面或语音重新核对指纹之前，不要向此人共享任何东西。
        </div>
      )}
      {busy && <p className="muted">正在处理（轮换密钥时需要重新加密所有条目）…</p>}
      {isOwner && !adding && (
        <Button kind="primary" onClick={() => setAdding(true)}>
          添加成员
        </Button>
      )}
      {isOwner && adding && members && (
        <AddMember
          vault={vault}
          existing={members}
          onDone={() => {
            setAdding(false);
            void reload();
          }}
        />
      )}
      <p className="hint">viewer 只读，editor 可增删改条目，只有所有者能管理成员。注意：viewer 在密码学上同样持有保管库密钥，只给信得过的朋友共享。</p>
    </Modal>
  );
}

function AddMember({ vault, existing, onDone }: { vault: VaultView; existing: MemberDto[]; onDone: () => void }) {
  const [email, setEmail] = useState('');
  const [found, setFound] = useState<{ userId: string; email: string; publicKey: string } | null>(null);
  const [role, setRole] = useState<'editor' | 'viewer'>('viewer');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const fp = useFingerprint(found?.publicKey);
  const contact = found ? verifiedContact(found.userId) : undefined;
  const mismatch = !!contact && contact.item.contact!.publicKey !== found?.publicKey;

  async function lookup() {
    setError(null);
    setFound(null);
    try {
      const r = await api.lookup(email.trim());
      if (r.userId === session.userId()) return setError('不能添加自己');
      if (existing.some((m) => m.userId === r.userId)) return setError('已经是成员了');
      setFound(r);
    } catch (e) {
      setError(errorMessage(e));
    }
  }

  async function verifyAndAdd() {
    if (!found || mismatch) return;
    setBusy(true);
    setError(null);
    try {
      if (!contact) {
        // Save the verified key (userId + publicKey) as an encrypted contact in the personal vault.
        const pv = session.personalVaultId()!;
        await session.saveItem(pv, null, {
          ...emptyItem('contact'),
          name: found.email,
          contact: { userId: found.userId, email: found.email, publicKey: found.publicKey, verifiedAt: new Date().toISOString() },
        });
      }
      await session.putMember(vault.id, found.userId, found.publicKey, role);
      onDone();
    } catch (e) {
      setError(errorMessage(e));
      setBusy(false);
    }
  }

  return (
    <div className="add-member">
      <div className="input-row">
        <TextField label="对方邮箱" type="email" value={email} onChange={setEmail} />
        <Button onClick={() => void lookup()} disabled={!email.includes('@')}>
          查找
        </Button>
      </div>
      {found && (
        <div className={`callout${mismatch ? ' danger' : ''}`}>
          {mismatch ? (
            <>
              <strong>公钥与核验记录不一致，已阻止共享。</strong>
              <div>记录的指纹：</div>
              <Fingerprint publicKey={contact!.item.contact!.publicKey} />
              <div>服务器现在返回的：</div>
              <code className="fingerprint">{fp}</code>
            </>
          ) : contact ? (
            <>
              <div>{found.email} 已在 {new Date(contact.item.contact!.verifiedAt).toLocaleDateString()} 核验过：</div>
              <code className="fingerprint">{fp}</code>
            </>
          ) : (
            <>
              <div>
                请通过<strong>微信语音或当面</strong>，让 {found.email} 在 “设置 → 我的公钥指纹” 里念出指纹，逐组核对：
              </div>
              <code className="fingerprint big">{fp}</code>
            </>
          )}
        </div>
      )}
      {found && !mismatch && (
        <div className="row">
          <select value={role} onChange={(e) => setRole(e.target.value as 'editor' | 'viewer')}>
            <option value="viewer">只读</option>
            <option value="editor">可编辑</option>
          </select>
          <Button kind="primary" disabled={busy} onClick={() => void verifyAndAdd()}>
            {contact ? '添加' : '指纹一致，已核验并添加'}
          </Button>
        </div>
      )}
      <ErrorText error={error} />
    </div>
  );
}
