import type { ReactNode } from "react";

export function Section({
  id,
  children,
  className = "",
}: {
  id?: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section id={id} className={`w-full ${className}`}>
      <div className="mx-auto max-w-[1180px] px-5 sm:px-8">{children}</div>
    </section>
  );
}

/* Used sparingly — the skill caps eyebrows at 1 per 3 sections. */
export function Eyebrow({ children }: { children: ReactNode }) {
  return (
    <div className="mono text-[11px] uppercase tracking-[0.22em] text-[color:var(--dim)]">
      {children}
    </div>
  );
}

export function Button({
  href,
  children,
  variant = "solid",
}: {
  href: string;
  children: ReactNode;
  variant?: "solid" | "outline";
}) {
  const base =
    "inline-flex items-center justify-center whitespace-nowrap rounded-md px-5 py-2.5 text-[14px] font-medium transition-all active:translate-y-[1px]";
  const styles =
    variant === "solid"
      ? "bg-[color:var(--accent)] text-[color:var(--accent-ink)] hover:brightness-110"
      : "border border-[color:var(--line)] text-[color:var(--text)] hover:border-[color:var(--accent)]";
  return (
    <a href={href} className={`${base} ${styles}`}>
      {children}
    </a>
  );
}
