import { useEffect, useMemo, useState } from 'react';
import { ItemEditor } from '../components/ItemEditor.js';
import { ItemView } from '../components/ItemView.js';
import { Generator } from '../components/Generator.js';
import { Button, ClipboardBanner, ErrorText, Modal, TextField } from '../components/ui.js';
import { hostOf, type ItemType } from '../lib/item.js';
import { errorMessage } from '../lib/api.js';
import { lockNow } from '../lib/autolock.js';
import { session, type PublicState } from '../state/session.js';
import { Settings } from './Settings.js';
import { VaultMembers } from './Sharing.js';
import { SecurityReport } from './SecurityReport.js';

type Filter = 'all' | 'favorite' | ItemType;
const FILTERS: [Filter, string][] = [
  ['all', '全部'],
  ['favorite', '收藏'],
  ['login', '登录'],
  ['note', '笔记'],
  ['card', '银行卡'],
  ['contact', '联系人'],
];

export function VaultApp({ st }: { st: PublicState }) {
  const vaults = session.vaults();
  const [vaultId, setVaultId] = useState<string | null>(null);
  const [filter, setFilter] = useState<Filter>('all');
  const [query, setQuery] = useState('');
  const [selected, setSelected] = useState<{ vaultId: string; id: string } | null>(null);
  const [editing, setEditing] = useState<{ vaultId: string; id: string | null; type?: ItemType } | null>(null);
  const [panel, setPanel] = useState<null | 'settings' | 'generator' | 'members' | 'newVault' | 'report'>(null);
  const [menu, setMenu] = useState(false);

  // Periodic sync while unlocked (and when the tab regains focus).
  useEffect(() => {
    const id = setInterval(() => void session.sync(), 60_000);
    const onFocus = () => void session.sync();
    window.addEventListener('focus', onFocus);
    return () => {
      clearInterval(id);
      window.removeEventListener('focus', onFocus);
    };
  }, []);

  const items = useMemo(() => {
    const q = query.trim().toLowerCase();
    return session
      .items(vaultId ?? undefined)
      .filter((it) => {
        const i = it.item;
        if (filter === 'favorite' && !i.favorite) return false;
        if (filter !== 'all' && filter !== 'favorite' && i.type !== filter) return false;
        if (filter === 'all' && i.type === 'contact') return false;
        if (!q) return true;
        return [i.name, i.username, i.notes, ...i.urls].some((s) => s.toLowerCase().includes(q));
      })
      .sort((a, b) => Number(b.item.favorite) - Number(a.item.favorite) || a.item.name.localeCompare(b.item.name, 'zh'));
    // st.version re-evaluates after every session change
  }, [vaultId, filter, query, st.version]); // eslint-disable-line react-hooks/exhaustive-deps

  const current = selected ? session.item(selected.vaultId, selected.id) : undefined;
  const currentVault = vaultId ? session.vault(vaultId) : undefined;
  const targetVault = vaultId ?? session.personalVaultId();
  const canWrite = (vid: string | null) => {
    const v = vid ? session.vault(vid) : undefined;
    return !!v && v.role !== 'viewer';
  };

  return (
    <div className="app">
      <header className="topbar">
        <button type="button" className="btn btn-ghost btn-sm only-mobile" onClick={() => setMenu(!menu)} aria-label="保管库菜单">
          ☰
        </button>
        <div className="brand small">
          <img src="/icon.svg" alt="" width={24} height={24} />
          <span>VPass</span>
        </div>
        <input className="search" type="search" placeholder="搜索名称、用户名、网址…" value={query} onChange={(e) => setQuery(e.target.value)} autoComplete="off" spellCheck={false} />
        <div className="topbar-actions">
          <span className={`sync-dot${st.lastError ? ' err' : st.syncing ? ' busy' : ''}`} title={st.lastError === 'offline' ? '离线' : st.lastError ? '同步失败' : st.lastSyncAt ? `已同步 ${new Date(st.lastSyncAt).toLocaleTimeString()}` : '未同步'} />
          <Button small kind="ghost" onClick={() => setPanel('generator')}>
            生成器
          </Button>
          <Button small kind="ghost" onClick={() => setPanel('settings')}>
            设置
          </Button>
          <Button small onClick={lockNow} title="立即锁定（Alt+L）">
            锁定
          </Button>
        </div>
      </header>
      {!st.online && <div className="banner">离线模式：显示的是本机缓存，修改需要联网。</div>}
      {st.integrityIssues.length > 0 && (
        <div className="banner danger" role="alert">
          <strong>有 {st.integrityIssues.length} 处数据无法验证，可能被篡改，已拒绝显示。</strong>
          <details>
            <summary>详情</summary>
            <ul>
              {st.integrityIssues.map((x, i) => (
                <li key={i}>{x}</li>
              ))}
            </ul>
          </details>
        </div>
      )}
      <div className="columns">
        <nav className={`sidebar${menu ? ' open' : ''}`}>
          <div className="nav-group">
            <button className={!vaultId ? 'active' : ''} onClick={() => (setVaultId(null), setMenu(false))}>
              所有保管库
            </button>
            {vaults.map((v) => (
              <button key={v.id} className={vaultId === v.id ? 'active' : ''} onClick={() => (setVaultId(v.id), setMenu(false))}>
                {v.kind === 'shared' ? '👥 ' : '🔒 '}
                {v.name}
                {v.role !== 'owner' && <span className="badge">{v.role === 'viewer' ? '只读' : '可编辑'}</span>}
              </button>
            ))}
            <Button small kind="ghost" onClick={() => setPanel('newVault')}>
              + 新建共享库
            </Button>
          </div>
          <div className="nav-group">
            {FILTERS.map(([f, label]) => (
              <button key={f} className={filter === f ? 'active' : ''} onClick={() => (setFilter(f), setMenu(false))}>
                {label}
              </button>
            ))}
          </div>
          <div className="nav-group">
            <button onClick={() => setPanel('report')}>安全报告</button>
            {currentVault?.kind === 'shared' && <button onClick={() => setPanel('members')}>成员与共享</button>}
          </div>
        </nav>
        <section className={`list${selected || editing ? ' hide-mobile' : ''}`}>
          <div className="list-head">
            <span className="muted">{items.length} 项</span>
            {canWrite(targetVault) && (
              <select
                className="new-select"
                value=""
                aria-label="新建条目"
                onChange={(e) => {
                  if (!targetVault || !e.target.value) return;
                  setSelected(null);
                  setEditing({ vaultId: targetVault, id: null, type: e.target.value as ItemType });
                }}
              >
                <option value="">+ 新建…</option>
                <option value="login">登录</option>
                <option value="note">安全笔记</option>
                <option value="card">银行卡</option>
              </select>
            )}
          </div>
          <ul>
            {items.map((it) => (
              <li key={it.id}>
                <button
                  className={selected?.id === it.id ? 'active' : ''}
                  onClick={() => {
                    setEditing(null);
                    setSelected({ vaultId: it.vaultId, id: it.id });
                  }}
                >
                  <span className="avatar">{(it.item.name || '?').slice(0, 1).toUpperCase()}</span>
                  <span className="li-text">
                    <span className="li-title">
                      {it.item.favorite && <span className="star">★</span>}
                      {it.item.name || '未命名'}
                    </span>
                    <span className="li-sub">{it.item.username || (it.item.urls[0] ? hostOf(it.item.urls[0]) : '') || (it.item.type === 'note' ? '安全笔记' : '')}</span>
                  </span>
                </button>
              </li>
            ))}
            {items.length === 0 && <li className="empty">{query ? '没有匹配的条目' : '这里还是空的'}</li>}
          </ul>
        </section>
        <main className={`detail${selected || editing ? '' : ' hide-mobile'}`}>
          {(selected || editing) && (
            <Button
              small
              kind="ghost"
              onClick={() => {
                setSelected(null);
                setEditing(null);
              }}
            >
              ← 返回
            </Button>
          )}
          {editing ? (
            <ItemEditor
              key={`${editing.vaultId}/${editing.id ?? 'new'}`}
              vaultId={editing.vaultId}
              existing={editing.id ? (session.item(editing.vaultId, editing.id) ?? null) : null}
              type={editing.type}
              onDone={(id) => {
                setEditing(null);
                setSelected(id ? { vaultId: editing.vaultId, id } : null);
              }}
            />
          ) : current ? (
            <ItemView
              it={current}
              canEdit={canWrite(current.vaultId)}
              onEdit={() => setEditing({ vaultId: current.vaultId, id: current.id })}
              onDelete={() => {
                if (!confirm(`删除“${current.item.name}”？`)) return;
                void session.deleteItem(current.vaultId, current.id).then(() => setSelected(null), (e) => alert(errorMessage(e)));
              }}
            />
          ) : (
            <div className="placeholder muted">选择一个条目</div>
          )}
        </main>
      </div>
      <ClipboardBanner />
      {panel === 'settings' && <Settings st={st} onClose={() => setPanel(null)} />}
      {panel === 'generator' && (
        <Modal title="密码生成器" onClose={() => setPanel(null)}>
          <Generator />
        </Modal>
      )}
      {panel === 'members' && currentVault && <VaultMembers vault={currentVault} onClose={() => setPanel(null)} />}
      {panel === 'newVault' && <NewVault onClose={(id) => (setPanel(null), id && setVaultId(id))} />}
      {panel === 'report' && <SecurityReport onClose={() => setPanel(null)} onOpen={(vid, id) => (setPanel(null), setSelected({ vaultId: vid, id }))} />}
    </div>
  );
}

function NewVault({ onClose }: { onClose: (id: string | null) => void }) {
  const [name, setName] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <Modal title="新建共享保管库" onClose={() => onClose(null)}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          setBusy(true);
          session.createSharedVault(name.trim()).then(onClose, (err) => {
            setError(errorMessage(err));
            setBusy(false);
          });
        }}
      >
        <TextField label="名称（会加密存储）" value={name} onChange={setName} autoFocus />
        <p className="hint">共享的单位是整个保管库。建好之后在“成员与共享”里添加已核验的联系人。</p>
        <ErrorText error={error} />
        <Button kind="primary" type="submit" disabled={!name.trim() || busy}>
          创建
        </Button>
      </form>
    </Modal>
  );
}
