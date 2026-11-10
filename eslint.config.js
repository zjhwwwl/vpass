// Blueprint section 10: ban Math.random, eval, new Function, dangerouslySetInnerHTML, console.log in
// production code and any localStorage/sessionStorage use. TypeScript strict is enforced by tsconfig.
import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import reactHooks from 'eslint-plugin-react-hooks';
import globals from 'globals';

const banned = [
  { selector: "MemberExpression[object.name='Math'][property.name='random']", message: '禁止 Math.random：用 crypto.getRandomValues / randombytes_buf' },
  { selector: "CallExpression[callee.name='eval']", message: '禁止 eval' },
  { selector: "NewExpression[callee.name='Function']", message: '禁止 new Function' },
  { selector: "CallExpression[callee.name='Function']", message: '禁止 Function()' },
  { selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']", message: '禁止 dangerouslySetInnerHTML：条目一律按纯文本渲染' },
  { selector: "MemberExpression[property.name=/^(innerHTML|outerHTML)$/]", message: '禁止 innerHTML/outerHTML' },
  { selector: "Identifier[name=/^(localStorage|sessionStorage)$/]", message: '禁止 localStorage/sessionStorage：密钥与明文不得落盘' },
  { selector: "MemberExpression[object.name='console'][property.name=/^(log|debug|info|trace)$/]", message: '生产代码禁止 console.log' },
];

export default tseslint.config(
  { ignores: ['**/dist/**', '**/coverage/**', '**/.wrangler/**', '**/node_modules/**', 'apps/web/public/sw.js', 'packages/crypto/src/wordlist.ts', 'playwright-report/**', 'test-results/**'] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['**/*.{ts,tsx}'],
    languageOptions: { globals: { ...globals.browser, ...globals.worker } },
    plugins: { 'react-hooks': reactHooks },
    rules: {
      'no-restricted-syntax': ['error', ...banned],
      'no-restricted-globals': ['error', 'localStorage', 'sessionStorage'],
      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'warn',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      '@typescript-eslint/no-non-null-assertion': 'off',
    },
  },
  {
    // Tests and tooling may log and use test-only shortcuts, but still no Math.random / eval.
    files: ['**/test/**', 'e2e/**', 'scripts/**', '**/*.config.ts'],
    languageOptions: { globals: { ...globals.node } },
    // Tests may read storage to assert it is empty.
    rules: { 'no-restricted-syntax': ['error', ...banned.slice(0, 4)], 'no-restricted-globals': 'off' },
  },
  { files: ['scripts/**/*.mjs', 'eslint.config.js'], languageOptions: { globals: globals.node } },
);
