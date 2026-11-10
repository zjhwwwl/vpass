import { useState, type FormEvent } from 'react';
import { parseTotp } from '@vpass/crypto';
import { emptyItem, withPasswordHistory, type Field, type Item, type ItemType } from '../lib/item.js';
import { errorMessage } from '../lib/api.js';
import { ConflictError, session, type DecryptedItem } from '../state/session.js';
import { Generator } from './Generator.js';
import { Button, ErrorText, Modal, TextField } from './ui.js';
import { ItemView } from './ItemView.js';

export function ItemEditor(props: { vaultId: string; existing: DecryptedItem | null; type?: ItemType; onDone: (id: string | null) => void }) {
  const [item, setItem] = useState<Item>(() => (props.existing ? structuredClone(props.existing.item) : emptyItem(props.type)));
  const [gen, setGen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [conflict, setConflict] = useState<ConflictError | null>(null);

  const set = <K extends keyof Item>(k: K, v: Item[K]) => setItem({ ...item, [k]: v });
  const setField = (idx: number, f: Partial<Field>) => set('fields', item.fields.map((x, i) => (i === idx ? { ...x, ...f } : x)));

  async function save(expected?: number | null, value = item) {
    setBusy(true);
    setError(null);
    try {
      if (value.totp) parseTotp(value.totp);
      const next = withPasswordHistory(props.existing?.item ?? null, { ...value, urls: value.urls.map((u) => u.trim()).filter(Boolean) });
      const id = await session.saveItem(props.vaultId, props.existing?.id ?? null, next, expected);
      props.onDone(id);
    } catch (e) {
      if (e instanceof ConflictError) setConflict(e);
      else setError(e instanceof Error && e.message === 'invalid_totp' ? 'TOTP 密钥格式不正确（Base32 或 otpauth:// 链接）' : errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  function submit(e: FormEvent) {
    e.preventDefault();
    void save();
  }

  return (
    <form className="item-editor" onSubmit={submit}>
      <h2>{props.existing ? '编辑' : '新建'}</h2>
      <TextField label="名称" value={item.name} onChange={(v) => set('name', v)} autoFocus />
      {item.type === 'login' && (
        <>
          <TextField label="用户名" value={item.username} onChange={(v) => set('username', v)} />
          <div className="field">
            <label>密码</label>
            <div className="input-row">
              <input className="mono" type="text" aria-label="密码" value={item.password} onChange={(e) => set('password', e.target.value)} autoComplete="off" spellCheck={false} />
              <Button small onClick={() => setGen(true)}>
                生成
              </Button>
            </div>
          </div>
          {item.urls.map((u, i) => (
            <div className="input-row" key={i}>
              <TextField label={i === 0 ? '网址' : `网址 ${i + 1}`} value={u} onChange={(v) => set('urls', item.urls.map((x, j) => (j === i ? v : x)))} placeholder="https://" />
              {item.urls.length > 1 && (
                <Button small kind="ghost" onClick={() => set('urls', item.urls.filter((_, j) => j !== i))}>
                  移除
                </Button>
              )}
            </div>
          ))}
          <Button small kind="ghost" onClick={() => set('urls', [...item.urls, ''])}>
            + 网址
          </Button>
          <TextField label="TOTP 密钥" value={item.totp} onChange={(v) => set('totp', v)} mono placeholder="Base32 密钥或 otpauth:// 链接" />
        </>
      )}
      {item.fields.map((f, i) => (
        <div className="custom-field" key={i}>
          <input className="label-input" value={f.label} onChange={(e) => setField(i, { label: e.target.value })} placeholder="字段名" autoComplete="off" />
          <input className="mono" type={f.hidden ? 'password' : 'text'} value={f.value} onChange={(e) => setField(i, { value: e.target.value })} autoComplete="off" spellCheck={false} />
          <label className="check">
            <input type="checkbox" checked={f.hidden} onChange={(e) => setField(i, { hidden: e.target.checked })} /> 隐藏
          </label>
          <Button small kind="ghost" onClick={() => set('fields', item.fields.filter((_, j) => j !== i))}>
            移除
          </Button>
        </div>
      ))}
      <Button small kind="ghost" onClick={() => set('fields', [...item.fields, { label: '', value: '', hidden: false }])}>
        + 自定义字段
      </Button>
      <TextField label="备注" value={item.notes} onChange={(v) => set('notes', v)} multiline />
      <label className="check">
        <input type="checkbox" checked={item.favorite} onChange={(e) => set('favorite', e.target.checked)} /> 收藏
      </label>
      <ErrorText error={error} />
      <div className="row">
        <Button kind="primary" type="submit" disabled={busy}>
          保存
        </Button>
        <Button onClick={() => props.onDone(props.existing?.id ?? null)}>取消</Button>
      </div>
      {gen && (
        <Modal title="密码生成器" onClose={() => setGen(false)}>
          <Generator
            onUse={(pw) => {
              set('password', pw);
              setGen(false);
            }}
          />
        </Modal>
      )}
      {conflict && (
        <Modal title="版本冲突" onClose={() => setConflict(null)} wide>
          <p>这个条目在别的设备上被修改过。选择要保留的版本：</p>
          <div className="conflict">
            <div>
              <h3>我的修改</h3>
              <ItemView it={{ id: '', vaultId: props.vaultId, revision: 0, updatedAt: Date.now(), item: conflict.mine }} canEdit={false} onEdit={() => {}} onDelete={() => {}} />
              <Button kind="primary" onClick={() => void save(conflict.serverRevision, conflict.mine).then(() => setConflict(null))}>
                保留我的版本
              </Button>
            </div>
            <div>
              <h3>服务器上的版本</h3>
              {conflict.theirs ? (
                <ItemView it={conflict.theirs} canEdit={false} onEdit={() => {}} onDelete={() => {}} />
              ) : (
                <p className="muted">（已被删除）</p>
              )}
              <Button
                onClick={() => {
                  setConflict(null);
                  void session.sync().then(() => props.onDone(conflict.theirs ? props.existing?.id ?? null : null));
                }}
              >
                使用服务器版本
              </Button>
            </div>
          </div>
        </Modal>
      )}
    </form>
  );
}
