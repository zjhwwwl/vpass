import { useState } from 'react';
import { downloadText } from '../lib/download.js';
import { Button, QrCode } from './ui.js';

/**
 * Emergency kit: email + Secret Key + recovery code, with a blank line for the master password.
 * Print it (or "Save as PDF" in the print dialog) — no PDF library, nothing leaves the browser.
 */
export function EmergencyKit(props: { email: string; secretKey: string; recoveryCode: string | null; onPrinted?: () => void }) {
  const [saved, setSaved] = useState(false);
  const origin = location.origin;
  const text = [
    'VPass 应急卡',
    '================',
    `网址：${origin}`,
    `邮箱：${props.email}`,
    `Secret Key：${props.secretKey}`,
    props.recoveryCode ? `恢复码：${props.recoveryCode}` : '',
    '主密码：________________________（手写，不要打印）',
    '',
    '保存在安全的地方（例如纸质存放在家里）。丢了主密码又没有恢复码，数据将永久无法找回。',
  ]
    .filter(Boolean)
    .join('\n');
  return (
    <div className="kit">
      <div className="kit-card print-area">
        <h3>VPass 应急卡</h3>
        <dl>
          <dt>网址</dt>
          <dd className="mono">{origin}</dd>
          <dt>邮箱</dt>
          <dd className="mono">{props.email}</dd>
          <dt>Secret Key</dt>
          <dd className="mono big">{props.secretKey}</dd>
          {props.recoveryCode && (
            <>
              <dt>恢复码</dt>
              <dd className="mono big">{props.recoveryCode}</dd>
            </>
          )}
          <dt>主密码</dt>
          <dd className="blank">（手写在这里）</dd>
        </dl>
        <div className="kit-qr">
          <QrCode text={props.secretKey} size={140} />
          <div className="hint">Secret Key 二维码</div>
        </div>
      </div>
      <div className="row">
        <Button
          kind="primary"
          onClick={() => {
            window.print();
            setSaved(true);
            props.onPrinted?.();
          }}
        >
          打印 / 存为 PDF
        </Button>
        <Button
          onClick={() => {
            downloadText('VPass-应急卡.txt', text);
            setSaved(true);
            props.onPrinted?.();
          }}
        >
          下载文本
        </Button>
      </div>
      {saved && <div className="hint">文件已生成。请打印出来或存放在离线位置，然后删除电脑上的副本。</div>}
    </div>
  );
}
