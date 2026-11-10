import { useCallback, useEffect, useState } from 'react';
import {
  DEFAULT_PASSPHRASE_OPTIONS,
  DEFAULT_PASSWORD_OPTIONS,
  generatePassphrase,
  generatePassword,
  passphraseEntropyBits,
  passwordEntropyBits,
  type PassphraseOptions,
  type PasswordOptions,
} from '@vpass/crypto';
import { Button, CopyButton } from './ui.js';

export function Generator({ onUse }: { onUse?: (pw: string) => void }) {
  const [mode, setMode] = useState<'chars' | 'words'>('chars');
  const [pw, setPw] = useState<PasswordOptions>({ ...DEFAULT_PASSWORD_OPTIONS });
  const [pp, setPp] = useState<PassphraseOptions>({ ...DEFAULT_PASSPHRASE_OPTIONS });
  const [value, setValue] = useState('');
  const [error, setError] = useState<string | null>(null);

  const regen = useCallback(async () => {
    try {
      setError(null);
      setValue(mode === 'chars' ? await generatePassword(pw) : await generatePassphrase(pp));
    } catch {
      setError('请至少选择一种字符');
    }
  }, [mode, pw, pp]);

  useEffect(() => {
    void regen();
  }, [regen]);

  const bits = mode === 'chars' ? passwordEntropyBits(pw) : passphraseEntropyBits(pp);
  const check = (k: 'lower' | 'upper' | 'digits' | 'symbols', label: string) => (
    <label className="check">
      <input type="checkbox" checked={pw[k]} onChange={(e) => setPw({ ...pw, [k]: e.target.checked })} /> {label}
    </label>
  );

  return (
    <div className="generator">
      <div className="tabs small">
        <button type="button" className={mode === 'chars' ? 'active' : ''} onClick={() => setMode('chars')}>
          随机字符
        </button>
        <button type="button" className={mode === 'words' ? 'active' : ''} onClick={() => setMode('words')}>
          单词短语
        </button>
      </div>
      <div className="gen-output mono" aria-live="polite">
        {value}
      </div>
      <div className="hint">约 {bits} 位熵 · 拒绝采样，无取模偏差</div>
      {mode === 'chars' ? (
        <div className="gen-opts">
          <label className="range">
            长度 {pw.length}
            <input type="range" min={8} max={64} value={pw.length} onChange={(e) => setPw({ ...pw, length: Number(e.target.value) })} />
          </label>
          {check('lower', 'a-z')}
          {check('upper', 'A-Z')}
          {check('digits', '0-9')}
          {check('symbols', '!@#')}
          <label className="check">
            <input type="checkbox" checked={!!pw.avoidAmbiguous} onChange={(e) => setPw({ ...pw, avoidAmbiguous: e.target.checked })} /> 去掉易混淆字符
          </label>
        </div>
      ) : (
        <div className="gen-opts">
          <label className="range">
            单词数 {pp.words}
            <input type="range" min={3} max={12} value={pp.words} onChange={(e) => setPp({ ...pp, words: Number(e.target.value) })} />
          </label>
          <label className="check">
            分隔符
            <select value={pp.separator} onChange={(e) => setPp({ ...pp, separator: e.target.value })}>
              <option value="-">-</option>
              <option value=" ">空格</option>
              <option value=".">.</option>
              <option value="_">_</option>
            </select>
          </label>
          <label className="check">
            <input type="checkbox" checked={pp.capitalize} onChange={(e) => setPp({ ...pp, capitalize: e.target.checked })} /> 首字母大写
          </label>
          <label className="check">
            <input type="checkbox" checked={pp.includeNumber} onChange={(e) => setPp({ ...pp, includeNumber: e.target.checked })} /> 加一个数字
          </label>
        </div>
      )}
      {error && <div className="error">{error}</div>}
      <div className="row">
        <Button onClick={() => void regen()}>重新生成</Button>
        <CopyButton value={value} small={false} />
        {onUse && (
          <Button kind="primary" onClick={() => onUse(value)}>
            使用这个密码
          </Button>
        )}
      </div>
    </div>
  );
}
