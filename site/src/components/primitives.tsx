import { motion } from "framer-motion";
import { cn } from "@/lib/utils";

export const REPO = "https://github.com/Piyush-4007/Cleave";

export function Section({
  id,
  className,
  inner,
  children,
}: {
  id?: string;
  className?: string;
  inner?: string;
  children: React.ReactNode;
}) {
  return (
    <section id={id} className={cn("relative px-4 py-24 sm:px-6 md:py-32", className)}>
      <div className={cn("mx-auto w-full max-w-7xl", inner)}>{children}</div>
    </section>
  );
}

export function Kicker({ n, children, dark }: { n: string; children: React.ReactNode; dark?: boolean }) {
  return (
    <div className={cn("flex items-center gap-3 font-mono text-xs uppercase tracking-[0.14em]", dark ? "text-mute-dark" : "text-mute")}>
      <span className={cn("rounded-full px-2 py-0.5", dark ? "bg-lime text-ink" : "bg-ink text-paper")}>{n}</span>
      {children}
    </div>
  );
}

export function Title({ children, className }: { children: React.ReactNode; className?: string }) {
  return <h2 className={cn("display mt-6 text-[44px] text-balance sm:text-6xl lg:text-[76px]", className)}>{children}</h2>;
}

export function Reveal({ children, delay = 0, className }: { children: React.ReactNode; delay?: number; className?: string }) {
  return (
    <motion.div
      className={className}
      initial={{ opacity: 0, y: 24 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, amount: 0.2 }}
      transition={{ duration: 0.6, delay, ease: [0.16, 1, 0.3, 1] }}
    >
      {children}
    </motion.div>
  );
}

export function Button({
  href,
  onClick,
  children,
  variant = "ink",
  className,
}: {
  href?: string;
  onClick?: () => void;
  children: React.ReactNode;
  variant?: "ink" | "lime" | "outline" | "outline-dark";
  className?: string;
}) {
  const cls = cn(
    "group inline-flex min-h-12 cursor-pointer items-center justify-center gap-2 rounded-full px-6 text-[15px] font-semibold transition-all duration-200 active:scale-[0.98]",
    variant === "ink" && "bg-ink text-paper hover:bg-ink-3",
    variant === "lime" && "bg-lime text-ink hover:brightness-95",
    variant === "outline" && "border border-ink/25 text-ink hover:border-ink hover:bg-ink/5",
    variant === "outline-dark" && "border border-white/25 text-paper hover:border-white hover:bg-white/5",
    className,
  );
  if (href) {
    return (
      <a href={href} className={cls}>
        {children}
      </a>
    );
  }
  return (
    <button type="button" onClick={onClick} className={cls}>
      {children}
    </button>
  );
}

/** The Cleave mark (blade bow), simplified for small sizes. */
export function Mark({ className, arrow = "#d4f53c" }: { className?: string; arrow?: string }) {
  const limb = (
    <>
      <path d="M17 32C16 19 26 9 43 4 45 5 46 7 45 9 43 8 42 8 41 9 29 14 22 22 21 32z" />
      <path d="M19.5 20 11 14 22 16.5z" />
      <path d="M27 12 23 4 30 9.5z" />
      <path d="M20 27 14 25 20.5 23.5z" />
    </>
  );
  return (
    <svg viewBox="0 0 64 64" fill="currentColor" aria-hidden className={className}>
      {limb}
      <g transform="translate(0 68) scale(1 -1)">{limb}</g>
      <path d="M44 8 53 34 44 60" fill="none" stroke="currentColor" strokeWidth=".9" />
      <path d="M15 29h7v10h-7z" />
      <path d="M6 34H57" stroke="currentColor" strokeWidth="1.6" />
      <path d="M1 34 11 28.5 8.5 34 11 39.5z" />
      <path d="M53 34 62 26 58.5 34 62 42zM47.5 34 56 27.5 53 34 56 40.5z" fill={arrow} />
    </svg>
  );
}

export function GithubMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 16 16" fill="currentColor" aria-hidden className={className}>
      <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" />
    </svg>
  );
}
