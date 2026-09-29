/* The "blade bow" mark (logo 6c), theme-aware via currentColor.
   `accentArrow` tints the arrowhead with the brand accent (the Signal-orange move). */
export function Mark({ size = 28, accentArrow = false }: { size?: number; accentArrow?: boolean }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="currentColor" aria-hidden="true">
      <path d="M17 32C16 19 26 9 43 4 45 5 46 7 45 9 43 8 42 8 41 9 29 14 22 22 21 32z" />
      <path d="M19.5 20 11 14 22 16.5z" />
      <path d="M27 12 23 4 30 9.5z" />
      <path d="M20 27 14 25 20.5 23.5z" />
      <g transform="translate(0 68) scale(1 -1)">
        <path d="M17 32C16 19 26 9 43 4 45 5 46 7 45 9 43 8 42 8 41 9 29 14 22 22 21 32z" />
        <path d="M19.5 20 11 14 22 16.5z" />
        <path d="M27 12 23 4 30 9.5z" />
        <path d="M20 27 14 25 20.5 23.5z" />
      </g>
      <path d="M44 8 53 34 44 60" fill="none" stroke="currentColor" strokeWidth=".7" />
      <path d="M15 29h7v10h-7z" />
      <path d="M18.5 25.5 22 34 18.5 42.5 15 34z" fill="none" stroke="currentColor" strokeWidth=".8" />
      <path d="M26 18V50" stroke="currentColor" strokeWidth=".4" />
      <circle cx="26" cy="34" r="3.2" fill="none" stroke="currentColor" strokeWidth=".5" />
      <path d="M6 34H57" stroke="currentColor" strokeWidth="1.4" />
      <path d="M1 34 11 28.5 8.5 34 11 39.5z" />
      <path
        d="M53 34 62 26 58.5 34 62 42zM47.5 34 56 27.5 53 34 56 40.5z"
        fill={accentArrow ? "var(--accent)" : "currentColor"}
      />
      <path d="M50 34 54 22M50 34 54 46" stroke="currentColor" strokeWidth=".5" />
    </svg>
  );
}

export function Wordmark({ markSize = 26 }: { markSize?: number }) {
  return (
    <a href="#top" className="flex items-center gap-2.5 text-[color:var(--text)] no-underline">
      <Mark size={markSize} accentArrow />
      <span className="display text-[19px] leading-none">Cleave</span>
    </a>
  );
}
