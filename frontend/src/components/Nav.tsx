import { useState } from "react";
import { GithubLogo, List, X } from "@phosphor-icons/react";
import { Wordmark } from "./Logo";
import { ThemeToggle } from "./ThemeToggle";
import { Button } from "./ui";

const LINKS = [
  ["Problem", "#problem"],
  ["How it works", "#method"],
  ["Trust", "#trust"],
  ["Compare", "#compare"],
];

export function Nav() {
  const [open, setOpen] = useState(false);
  return (
    <header className="sticky top-0 z-40 border-b border-[color:var(--line)] bg-[color:var(--bg)]/85 backdrop-blur-md">
      <div className="mx-auto flex h-[68px] max-w-[1180px] items-center justify-between px-5 sm:px-8">
        <Wordmark />

        <nav className="hidden items-center gap-8 md:flex">
          {LINKS.map(([label, href]) => (
            <a
              key={href}
              href={href}
              className="text-[14px] text-[color:var(--muted)] transition-colors hover:text-[color:var(--text)]"
            >
              {label}
            </a>
          ))}
        </nav>

        <div className="flex items-center gap-2.5">
          <a
            href="https://github.com/Piyush-4007/Cleave"
            aria-label="GitHub repository"
            className="hidden h-9 w-9 place-items-center rounded-md border border-[color:var(--line)] text-[color:var(--muted)] transition-colors hover:text-[color:var(--text)] sm:grid"
          >
            <GithubLogo size={18} />
          </a>
          <a
            href="/dashboard"
            className="mono hidden text-[13px] text-[color:var(--muted)] transition-colors hover:text-[color:var(--accent)] sm:block"
          >
            live demo →
          </a>
          <ThemeToggle />
          <div className="hidden sm:block">
            <Button href="#start">Get started</Button>
          </div>
          <button
            className="grid h-9 w-9 place-items-center rounded-md border border-[color:var(--line)] text-[color:var(--text)] md:hidden"
            onClick={() => setOpen((o) => !o)}
            aria-label="Menu"
          >
            {open ? <X size={18} /> : <List size={18} />}
          </button>
        </div>
      </div>

      {open && (
        <nav className="border-t border-[color:var(--line)] px-5 py-4 md:hidden">
          <div className="flex flex-col gap-4">
            {LINKS.map(([label, href]) => (
              <a
                key={href}
                href={href}
                onClick={() => setOpen(false)}
                className="text-[15px] text-[color:var(--text-2)]"
              >
                {label}
              </a>
            ))}
            <Button href="#start">Get started</Button>
          </div>
        </nav>
      )}
    </header>
  );
}
