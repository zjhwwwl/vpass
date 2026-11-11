// Minimal line icons in the spirit of SF Symbols. Inline SVG: no icon font, no CDN, CSP-safe.
const PATHS = {
  lock: 'M7 10V7a5 5 0 0 1 10 0v3M5.5 10h13a1.5 1.5 0 0 1 1.5 1.5v8a1.5 1.5 0 0 1-1.5 1.5h-13A1.5 1.5 0 0 1 4 19.5v-8A1.5 1.5 0 0 1 5.5 10Z',
  people: 'M9 11a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7Zm-6 9c0-3.3 2.7-6 6-6s6 2.7 6 6M16 4.5a3.5 3.5 0 0 1 0 6.5m2.5 9c0-2.6-1.4-4.8-3.5-5.6',
  grid: 'M4 4h7v7H4zM13 4h7v7h-7zM4 13h7v7H4zM13 13h7v7h-7z',
  star: 'm12 3.5 2.6 5.3 5.9.9-4.3 4.1 1 5.8-5.2-2.7-5.2 2.7 1-5.8-4.3-4.1 5.9-.9z',
  key: 'M14.5 9.5a4.5 4.5 0 1 0-4 4.47V14H12v2h2v2h2v2h4v-3.5l-5.47-5.47A4.5 4.5 0 0 0 14.5 9.5ZM8.5 9a1 1 0 1 0 0-.01',
  note: 'M6 3.5h9l4 4V20a.5.5 0 0 1-.5.5h-12A.5.5 0 0 1 6 20zM15 3.5V8h4M9 12h7M9 15.5h7',
  card: 'M3.5 6.5h17a1 1 0 0 1 1 1v9a1 1 0 0 1-1 1h-17a1 1 0 0 1-1-1v-9a1 1 0 0 1 1-1ZM2.5 10h19M6 14.5h4',
  person: 'M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8Zm-7.5 8.5c0-4 3.4-6.5 7.5-6.5s7.5 2.5 7.5 6.5',
  shield: 'M12 3 4.5 6v5.5c0 4.6 3.2 8.4 7.5 9.5 4.3-1.1 7.5-4.9 7.5-9.5V6zM9 12l2 2 4-4',
  gear: 'M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Zm7.4-1.8.1-1.2-.1-1.2 2-1.6-2-3.4-2.4.9a7.6 7.6 0 0 0-2-1.2L14.6 3h-4l-.4 2.5a7.6 7.6 0 0 0-2 1.2l-2.4-.9-2 3.4 2 1.6-.1 1.2.1 1.2-2 1.6 2 3.4 2.4-.9c.6.5 1.3.9 2 1.2l.4 2.5h4l.4-2.5c.7-.3 1.4-.7 2-1.2l2.4.9 2-3.4z',
  wand: 'm5 19 10-10m-2-2 2 2M17 3v3m-1.5-1.5h3M20 9v2m-1-1h2M9 4v2M8 5h2',
  plus: 'M12 5v14M5 12h14',
  search: 'M10.5 17a6.5 6.5 0 1 0 0-13 6.5 6.5 0 0 0 0 13Zm4.6-1.9L20 20',
  chevronLeft: 'M15 5l-7 7 7 7',
  chevronRight: 'M9 5l7 7-7 7',
  menu: 'M4 7h16M4 12h16M4 17h16',
  copy: 'M9 9h10.5v11H9zM15 9V4.5H4.5V15H9',
  eye: 'M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Zm9.5 3a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z',
  eyeOff: 'M3 3l18 18M10.6 6a9.9 9.9 0 0 1 1.4-.1c6 0 9.5 6.5 9.5 6.5a17 17 0 0 1-2.7 3.4M6.6 6.6A17.3 17.3 0 0 0 2.5 12S6 18.5 12 18.5c1.9 0 3.5-.6 4.9-1.5M9.9 9.9a3 3 0 0 0 4.2 4.2',
  trash: 'M4.5 7h15M10 11v6m4-6v6M6 7l1 13h10l1-13M9 7V4h6v3',
  pencil: 'M4 20h4L19 9l-4-4L4 16zM13.5 6.5l4 4',
  close: 'M6 6l12 12M18 6 6 18',
  link: 'M10 14a4.5 4.5 0 0 0 6.4 0l3-3a4.5 4.5 0 0 0-6.4-6.4l-1 1M14 10a4.5 4.5 0 0 0-6.4 0l-3 3a4.5 4.5 0 0 0 6.4 6.4l1-1',
  warning: 'M12 4 2.5 20h19zM12 10v4.5m0 2.5v.01',
} as const;

export type IconName = keyof typeof PATHS;

export function Icon({ name, size = 18, className }: { name: IconName; size?: number; className?: string }) {
  return (
    <svg
      className={`icon${className ? ` ${className}` : ''}`}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.7}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d={PATHS[name]} />
    </svg>
  );
}
