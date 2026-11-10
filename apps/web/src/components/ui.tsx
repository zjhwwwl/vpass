import { useEffect, useId, useRef, useState, type ReactNode } from 'react';
import QRCode from 'qrcode';
import { copySecret, onClipboardCountdown } from '../lib/clipboard.js';
import { session } from '../state/session.js';

export function Button(props: {
  children: ReactNode;
  onClick?: () => void;
  kind?: 'primary' | 'secondary' | 'danger' | 'ghost';
  type?: 'button' | 'submit';
  disabled?: boolean;
  small?: boolean;
  title?: string;
}) {
  return (
    <button
      type={props.type ?? 'button'}
      className={`btn btn-${props.kind ?? 'secondary'}${props.small ? ' btn-sm' : ''}`}
      onClick={props.onClick}
      disabled={props.disabled}
      title={props.title}
    >
      {props.children}
    </button>
  );
}

export function TextField(props: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  type?: string;
  placeholder?: string;
  autoComplete?: string;
  autoFocus?: boolean;
  required?: boolean;
  hint?: ReactNode;
  mono?: boolean;
  multiline?: boolean;
  name?: string;
}) {
  const id = useId();
  return (
    <div className="field">
      <label htmlFor={id}>{props.label}</label>
      {props.multiline ? (
        <textarea id={id} value={props.value} onChange={(e) => props.onChange(e.target.value)} placeholder={props.placeholder} rows={4} spellCheck={false} autoComplete="off" />
      ) : (
        <input
          id={id}
          name={props.name}
          className={props.mono ? 'mono' : undefined}
          type={props.type ?? 'text'}
          value={props.value}
          onChange={(e) => props.onChange(e.target.value)}
          placeholder={props.placeholder}
          autoComplete={props.autoComplete ?? 'off'}
          autoFocus={props.autoFocus}
          required={props.required}
          spellCheck={false}
          autoCapitalize="off"
          autoCorrect="off"
        />
      )}
      {props.hint && <div className="hint">{props.hint}</div>}
    </div>
  );
}

/** Master password input: autocomplete=current-password (or new-password), spellcheck off. */
export function PasswordField(props: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  autoComplete?: 'current-password' | 'new-password' | 'off';
  autoFocus?: boolean;
  hint?: ReactNode;
  name?: string;
}) {
  const id = useId();
  const [show, setShow] = useState(false);
  return (
    <div className="field">
      <label htmlFor={id}>{props.label}</label>
      <div className="input-row">
        <input
          id={id}
          name={props.name}
          type={show ? 'text' : 'password'}
          value={props.value}
          onChange={(e) => props.onChange(e.target.value)}
          autoComplete={props.autoComplete ?? 'current-password'}
          autoFocus={props.autoFocus}
          spellCheck={false}
          autoCapitalize="off"
          autoCorrect="off"
        />
        <button type="button" className="btn btn-ghost btn-sm" onClick={() => setShow(!show)} aria-label={show ? '隐藏' : '显示'}>
          {show ? '隐藏' : '显示'}
        </button>
      </div>
      {props.hint && <div className="hint">{props.hint}</div>}
    </div>
  );
}

export function Modal(props: { title: string; onClose: () => void; children: ReactNode; wide?: boolean }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && props.onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [props]);
  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && props.onClose()}>
      <div className={`modal${props.wide ? ' modal-wide' : ''}`} role="dialog" aria-modal="true" aria-label={props.title}>
        <div className="modal-head">
          <h2>{props.title}</h2>
          <button type="button" className="btn btn-ghost btn-sm" onClick={props.onClose} aria-label="关闭">
            ✕
          </button>
        </div>
        <div className="modal-body">{props.children}</div>
      </div>
    </div>
  );
}

export function ErrorText({ error }: { error: string | null }) {
  return error ? (
    <div className="error" role="alert">
      {error}
    </div>
  ) : null;
}

/** Argon2id progress: libsodium gives no callback, so this animates against the measured typical duration. */
export function KdfProgress({ label = '正在派生密钥（Argon2id）…' }: { label?: string }) {
  const [p, setP] = useState(0);
  useEffect(() => {
    const t0 = performance.now();
    const id = setInterval(() => setP(Math.min(0.95, 1 - Math.exp(-(performance.now() - t0) / 700))), 50);
    return () => clearInterval(id);
  }, []);
  return (
    <div className="kdf-progress" aria-live="polite">
      <div className="hint">{label}</div>
      <progress max={1} value={p} />
    </div>
  );
}

export function QrCode({ text, size = 220 }: { text: string; size?: number }) {
  const [src, setSrc] = useState<string | null>(null);
  useEffect(() => {
    let alive = true;
    QRCode.toDataURL(text, { errorCorrectionLevel: 'M', margin: 2, width: size }).then((u) => alive && setSrc(u));
    return () => {
      alive = false;
    };
  }, [text, size]);
  return src ? <img className="qr" src={src} width={size} height={size} alt="二维码" /> : <div className="qr" />;
}

export function CopyButton({ value, label = '复制', small = true }: { value: string; label?: string; small?: boolean }) {
  const [done, setDone] = useState(false);
  const secs = session.getSnapshot().settings.clipboardSeconds;
  return (
    <Button
      small={small}
      kind="ghost"
      title={`复制后 ${secs} 秒自动清空剪贴板（尽力而为）`}
      onClick={() => {
        void copySecret(value, secs).then(() => {
          setDone(true);
          setTimeout(() => setDone(false), 1200);
        });
      }}
    >
      {done ? '已复制' : label}
    </Button>
  );
}

export function ClipboardBanner() {
  const [left, setLeft] = useState<number | null>(null);
  useEffect(() => onClipboardCountdown(setLeft), []);
  if (left === null) return null;
  return <div className="toast">剪贴板将在 {left} 秒后清空（浏览器只能尽力而为，剪贴板历史工具可能已保存）</div>;
}

const STRENGTH = ['极弱', '很弱', '弱', '中', '强'];

/** zxcvbn is ~800 KB: loaded lazily, only on screens that set a master password. */
export function StrengthMeter({ password, userInputs = [] }: { password: string; userInputs?: string[] }) {
  const [score, setScore] = useState<number | null>(null);
  const [feedback, setFeedback] = useState('');
  const ref = useRef(0);
  useEffect(() => {
    const n = ++ref.current;
    if (!password) {
      setScore(null);
      return;
    }
    void import('zxcvbn').then(({ default: zxcvbn }) => {
      if (n !== ref.current) return;
      const r = zxcvbn(password, userInputs);
      setScore(r.score);
      setFeedback(r.feedback.warning || '');
    });
  }, [password, userInputs]);
  if (score === null) return null;
  return (
    <div className="strength">
      <div className={`strength-bar s${score}`}>
        <span />
      </div>
      <div className="hint">
        强度：{STRENGTH[score]}
        {score < 3 ? '（至少需要“强”以上，即 zxcvbn ≥ 3）' : ''}
        {feedback ? ` · ${feedback}` : ''}
      </div>
    </div>
  );
}

export async function passwordScore(password: string, userInputs: string[] = []): Promise<number> {
  const { default: zxcvbn } = await import('zxcvbn');
  return zxcvbn(password, userInputs).score;
}
