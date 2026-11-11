import { useEffect, useRef, useState } from 'react';
import type { ItemType } from '../lib/item.js';
import { Icon, type IconName } from './Icon.js';

const OPTIONS: [ItemType, string, IconName][] = [
  ['login', '登录', 'key'],
  ['note', '安全笔记', 'note'],
  ['card', '银行卡', 'card'],
];

/** "+" button that opens a small yellow notepad page instead of a native <select> popup (which can't be styled). */
export function NewItemMenu({ onPick }: { onPick: (t: ItemType) => void }) {
  const [open, setOpen] = useState(false);
  const wrap = useRef<HTMLDivElement>(null);
  const items = useRef<(HTMLButtonElement | null)[]>([]);
  const btn = useRef<HTMLButtonElement>(null);
  const menu = useRef<HTMLDivElement>(null);

  // The list column scrolls (overflow: auto), which would clip an absolutely positioned menu,
  // so the page is placed with position: fixed next to the button.
  const place = () => {
    const b = btn.current?.getBoundingClientRect();
    const m = menu.current;
    if (!b || !m) return;
    m.style.top = `${Math.round(b.bottom + 8)}px`;
    m.style.right = `${Math.round(Math.max(8, window.innerWidth - b.right - 4))}px`;
  };

  useEffect(() => {
    if (!open) return;
    place();
    items.current[0]?.focus({ preventScroll: true });
    const onDown = (e: PointerEvent) => {
      if (!wrap.current?.contains(e.target as Node)) setOpen(false);
    };
    const close = () => setOpen(false);
    window.addEventListener('pointerdown', onDown);
    window.addEventListener('resize', close);
    window.addEventListener('scroll', close, true);
    return () => {
      window.removeEventListener('pointerdown', onDown);
      window.removeEventListener('resize', close);
      window.removeEventListener('scroll', close, true);
    };
  }, [open]);

  const onKey = (e: React.KeyboardEvent) => {
    const list = items.current.filter(Boolean) as HTMLButtonElement[];
    const i = list.indexOf(document.activeElement as HTMLButtonElement);
    if (e.key === 'Escape') {
      setOpen(false);
      wrap.current?.querySelector<HTMLButtonElement>('.new-btn')?.focus();
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      list[(i + 1) % list.length]?.focus();
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      list[(i - 1 + list.length) % list.length]?.focus();
    }
  };

  return (
    <div className="new-menu-wrap" ref={wrap} onKeyDown={onKey}>
      <button ref={btn} type="button" className="new-btn" aria-label="新建条目" title="新建" aria-haspopup="menu" aria-expanded={open} onClick={() => setOpen(!open)}>
        <Icon name="plus" />
      </button>
      {open && (
        <div ref={menu} className="notepad-menu" role="menu" aria-label="新建条目">
          <div className="notepad-title">新建…</div>
          {OPTIONS.map(([type, label, icon], k) => (
            <button
              key={type}
              type="button"
              role="menuitem"
              ref={(el) => {
                items.current[k] = el;
              }}
              onClick={() => {
                setOpen(false);
                onPick(type);
              }}
            >
              <Icon name={icon} size={16} />
              {label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
