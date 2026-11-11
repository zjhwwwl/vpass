import { useState, type ReactNode } from 'react';
import { hostOf, safeHttpUrl, type Item } from '../lib/item.js';
import type { DecryptedItem } from '../state/session.js';
import { Icon } from './Icon.js';
import { TotpCode } from './TotpCode.js';
import { Button, CopyButton } from './ui.js';

const TYPE_LABEL: Record<Item['type'], string> = { login: '登录', note: '安全笔记', card: '银行卡', contact: '联系人' };

const GRADIENTS: [string, string][] = [
  ['#64d2ff', '#0a84ff'],
  ['#ff9f0a', '#ff6b00'],
  ['#30d158', '#1f9e46'],
  ['#bf5af2', '#8944ab'],
  ['#ff6482', '#ff2d55'],
  ['#5e5ce6', '#3634a3'],
  ['#66d4cf', '#2ba8a1'],
  ['#ffd60a', '#e6a700'],
];

/** Rounded-square monogram with a stable color per name (colors via CSSOM, allowed by the CSP). */
export function Avatar({ name, size }: { name: string; size?: 'lg' }) {
  let h = 0;
  for (const ch of name) h = (h * 31 + ch.charCodeAt(0)) | 0;
  const [a1, a2] = GRADIENTS[Math.abs(h) % GRADIENTS.length]!;
  return (
    <span className={`avatar${size ? ` ${size}` : ''}`} ref={(el) => (el?.style.setProperty('--a1', a1), el?.style.setProperty('--a2', a2))}>
      {(name || '?').slice(0, 1).toUpperCase()}
    </span>
  );
}

function Secret({ value }: { value: string }) {
  const [show, setShow] = useState(false);
  return (
    <>
      <div className="prop-value mono">{show ? value : '••••••••••••'}</div>
      <Actions>
        <button type="button" className="icon-btn" onClick={() => setShow(!show)} aria-label={show ? '隐藏' : '显示'} title={show ? '隐藏' : '显示'}>
          <Icon name={show ? 'eyeOff' : 'eye'} />
        </button>
        <CopyButton value={value} />
      </Actions>
    </>
  );
}

/** Rendered after the value; moved to the right by the row layout. */
function Actions({ children }: { children: ReactNode }) {
  return <span className="prop-actions-slot">{children}</span>;
}

function Prop({ label, children }: { label: string; children: ReactNode }) {
  // Children may include an <Actions> block: split it out so it sits on the right.
  const kids = Array.isArray(children) ? children : [children];
  return (
    <div className="prop">
      <div className="prop-main">
        <div className="prop-label">{label}</div>
        {kids}
      </div>
    </div>
  );
}

export function ItemView({ it, canEdit, onEdit, onDelete }: { it: DecryptedItem; canEdit: boolean; onEdit: () => void; onDelete: () => void }) {
  const i = it.item;
  const [history, setHistory] = useState(false);
  const urls = i.urls.filter(Boolean);
  const hasProps = i.username || i.password || i.totp || urls.length || i.fields.length || i.contact;
  return (
    <div className="item-view detail-inner">
      <div className="item-head">
        <div className="title">
          <Avatar name={i.name} />
          <div>
            <h2>
              {i.favorite && <span className="star">★</span>}
              {i.name || '未命名'}
            </h2>
            <div className="muted small">{TYPE_LABEL[i.type]}</div>
          </div>
        </div>
        {canEdit && (
          <div className="row">
            <Button onClick={onEdit}>
              <Icon name="pencil" size={15} /> 编辑
            </Button>
            <button type="button" className="icon-btn danger" onClick={onDelete} aria-label="删除" title="删除">
              <Icon name="trash" />
            </button>
          </div>
        )}
      </div>
      {hasProps ? (
        <div className="props">
          {i.username && (
            <Prop label="用户名">
              <div className="prop-value">{i.username}</div>
              <Actions>
                <CopyButton value={i.username} />
              </Actions>
            </Prop>
          )}
          {i.password && (
            <Prop label="密码">
              <Secret value={i.password} />
            </Prop>
          )}
          {i.totp && (
            <Prop label="一次性验证码">
              <TotpCode secret={i.totp} />
            </Prop>
          )}
          {urls.map((u, k) => {
            const href = safeHttpUrl(u);
            return (
              <Prop key={k} label={urls.length > 1 ? `网址 ${k + 1}` : '网址'}>
                {href ? (
                  <a className="prop-value" href={href} target="_blank" rel="noopener noreferrer">
                    {hostOf(u)}
                  </a>
                ) : (
                  <div className="prop-value mono">{u}</div>
                )}
                {href && (
                  <Actions>
                    <a className="icon-btn" href={href} target="_blank" rel="noopener noreferrer" aria-label="打开网址" title="打开网址">
                      <Icon name="link" />
                    </a>
                  </Actions>
                )}
              </Prop>
            );
          })}
          {i.fields.map((f, k) => (
            <Prop key={k} label={f.label || '字段'}>
              {f.hidden ? (
                <Secret value={f.value} />
              ) : (
                <>
                  <div className="prop-value">{f.value}</div>
                  <Actions>
                    <CopyButton value={f.value} />
                  </Actions>
                </>
              )}
            </Prop>
          ))}
          {i.contact && (
            <>
              <Prop label="联系人邮箱">
                <div className="prop-value">{i.contact.email}</div>
              </Prop>
              <Prop label="指纹核验时间">
                <div className="prop-value">{new Date(i.contact.verifiedAt).toLocaleString()}</div>
              </Prop>
            </>
          )}
        </div>
      ) : null}
      {i.notes && (
        <div className="notes">
          <div className="prop-label">备注</div>
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
            <div className="props">
              {i.passwordHistory.map((h, k) => (
                <Prop key={k} label={new Date(h.changedAt).toLocaleString()}>
                  <Secret value={h.value} />
                </Prop>
              ))}
            </div>
          )}
        </div>
      )}
      <div className="meta">修改于 {new Date(it.updatedAt).toLocaleString()}</div>
    </div>
  );
}
