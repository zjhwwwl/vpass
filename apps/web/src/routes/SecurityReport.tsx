import { useEffect, useState } from 'react';
import { Modal } from '../components/ui.js';
import { session, type DecryptedItem } from '../state/session.js';

/** Local-only report: weak and reused passwords. (HIBP breach lookup is off: CSP allows no third-party connections.) */
export function SecurityReport({ onClose, onOpen }: { onClose: () => void; onOpen: (vaultId: string, id: string) => void }) {
  const [weak, setWeak] = useState<DecryptedItem[] | null>(null);
  const logins = session.items().filter((i) => i.item.type === 'login' && i.item.password);
  const groups = new Map<string, DecryptedItem[]>();
  for (const it of logins) groups.set(it.item.password, [...(groups.get(it.item.password) ?? []), it]);
  const reused = [...groups.values()].filter((g) => g.length > 1);

  useEffect(() => {
    void import('zxcvbn').then(({ default: zxcvbn }) => setWeak(logins.filter((it) => zxcvbn(it.item.password.slice(0, 100)).score < 3)));
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const row = (it: DecryptedItem) => (
    <li key={it.id}>
      <button className="link" onClick={() => onOpen(it.vaultId, it.id)}>
        {it.item.name || '未命名'}
      </button>{' '}
      <span className="muted small">{it.item.username}</span>
    </li>
  );

  return (
    <Modal title="安全报告" onClose={onClose}>
      <p className="hint">只在本机统计，不发送任何数据。</p>
      <h3>弱密码（{weak ? weak.length : '…'}）</h3>
      <ul className="plain">{weak?.map(row)}</ul>
      <h3>重复使用的密码（{reused.length} 组）</h3>
      {reused.map((g, k) => (
        <ul className="plain group" key={k}>
          {g.map(row)}
        </ul>
      ))}
    </Modal>
  );
}
