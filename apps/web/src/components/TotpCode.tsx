import { useEffect, useMemo, useState } from 'react';
import { parseTotp, totp, totpRemaining } from '@vpass/crypto';
import { CopyButton } from './ui.js';

export function TotpCode({ secret }: { secret: string }) {
  const params = useMemo(() => {
    try {
      return parseTotp(secret);
    } catch {
      return null;
    }
  }, [secret]);
  const [now, setNow] = useState(() => Date.now() / 1000);
  const [code, setCode] = useState('');

  useEffect(() => {
    const id = setInterval(() => setNow(Date.now() / 1000), 1000);
    return () => clearInterval(id);
  }, []);

  const step = params ? Math.floor(now / params.period) : 0;
  useEffect(() => {
    if (!params) return;
    let alive = true;
    void totp(params, step * params.period).then((c) => alive && setCode(c));
    return () => {
      alive = false;
    };
  }, [params, step]);

  if (!params) return <span className="error">TOTP 密钥格式不正确</span>;
  const left = totpRemaining(params.period, now);
  const half = Math.floor(code.length / 2);
  return (
    <span className="totp">
      <span className="mono big">
        {code.slice(0, half)} {code.slice(half)}
      </span>
      <span className={`totp-ring${left <= 5 ? ' warn' : ''}`} title={`${left} 秒后刷新`}>
        {left}
      </span>
      <CopyButton value={code} />
    </span>
  );
}
