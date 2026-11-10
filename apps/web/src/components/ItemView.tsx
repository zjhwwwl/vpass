import { useState } from 'react';
import { hostOf, safeHttpUrl, type Item } from '../lib/item.js';
import type { DecryptedItem } from '../state/session.js';
import { TotpCode } from './TotpCode.js';
import { Button, CopyButton } from './ui.js';

const TYPE_LABEL: Record<Item['type'], string> = { login: '登录', note: '安全笔记', card: '银行卡', contact: '联系人' };

function Secret({ value }: { value: string }) {
  const [show, setShow] = useState(false);
  return (
    <span className="secret">
      <span className="mono">{show ? value : '••••••••••••'}</span>
      <Button small kind="ghost" onClick={() => setShow(!show)}>
        {show ? '隐藏' : '显示'}
      </Button>
      <CopyButton value={value} />
    </span>
  );
}

export function ItemView({ it, canEdit, onEdit, onDelete }: { it: DecryptedItem; canEdit: boolean; onEdit: () => void; onDelete: () => void }) {
  const i = it.item;
  const [history, setHistory] = useState(false);
  return (
    <div className="item-view">
      <div className="item-head">
        <div>
          <div className="muted small">{TYPE_LABEL[i.type]}</div>
          <h2>
            {i.favorite && <span className="star">★</span>}
            {i.name || '未命名'}
          </h2>
        </div>
        {canEdit && (
          <div className="row">
            <Button onClick={onEdit}>编辑</Button>
            <Button kind="danger" onClick={onDelete}>
              删除
            </Button>
          </div>
        )}
      </div>
      <dl className="props">
        {i.username && (
          <>
            <dt>用户名</dt>
            <dd>
              <span className="mono">{i.username}</span> <CopyButton value={i.username} />
            </dd>
          </>
        )}
        {i.password && (
          <>
            <dt>密码</dt>
            <dd>
              <Secret value={i.password} />
            </dd>
          </>
        )}
        {i.totp && (
          <>
            <dt>一次性验证码</dt>
            <dd>
              <TotpCode secret={i.totp} />
            </dd>
          </>
        )}
        {i.urls.filter(Boolean).map((u, k) => {
          const href = safeHttpUrl(u);
          return (
            <span key={k} className="contents">
              <dt>{k === 0 ? '网址' : ''}</dt>
              <dd>
                {href ? (
                  <a href={href} target="_blank" rel="noopener noreferrer">
                    {hostOf(u)}
                  </a>
                ) : (
                  <span className="mono">{u}</span>
                )}
              </dd>
            </span>
          );
        })}
        {i.fields.map((f, k) => (
          <span key={k} className="contents">
            <dt>{f.label || '字段'}</dt>
            <dd>
              {f.hidden ? (
                <Secret value={f.value} />
              ) : (
                <>
                  <span className="mono">{f.value}</span> <CopyButton value={f.value} />
                </>
              )}
            </dd>
          </span>
        ))}
        {i.contact && (
          <>
            <dt>联系人邮箱</dt>
            <dd className="mono">{i.contact.email}</dd>
            <dt>核验时间</dt>
            <dd>{new Date(i.contact.verifiedAt).toLocaleString()}</dd>
          </>
        )}
      </dl>
      {i.notes && (
        <div className="notes">
          <div className="muted small">备注</div>
          {/* Plain text only: React escapes; no HTML rendering anywhere. */}
          <pre>{i.notes}</pre>
        </div>
      )}
      {i.passwordHistory.length > 0 && (
        <div className="history">
          <Button small kind="ghost" onClick={() => setHistory(!history)}>
            密码历史（{i.passwordHistory.length}）
          </Button>
          {history && (
            <ul>
              {i.passwordHistory.map((h, k) => (
                <li key={k}>
                  <Secret value={h.value} /> <span className="muted small">{new Date(h.changedAt).toLocaleString()}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
      <div className="muted small">修改于 {new Date(it.updatedAt).toLocaleString()}</div>
    </div>
  );
}
