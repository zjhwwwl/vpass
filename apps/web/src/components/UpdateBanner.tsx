import { useEffect, useState } from 'react';
import { applyUpdate, onUpdateReady } from '../lib/sw-register.js';
import { Button } from './ui.js';

export function UpdateBanner() {
  const [ready, setReady] = useState(false);
  useEffect(() => onUpdateReady(() => setReady(true)), []);
  if (!ready) return null;
  return (
    <div className="banner update">
      有新版本可用。
      <Button small kind="primary" onClick={() => void applyUpdate()}>
        刷新
      </Button>
    </div>
  );
}
