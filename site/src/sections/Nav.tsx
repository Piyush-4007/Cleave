import { useEffect, useState } from "react";
import { Menu, X } from "lucide-react";
import { Button, GithubMark, Mark, REPO } from "@/components/primitives";
import { cn } from "@/lib/utils";
import { useAuth } from "@/lib/auth";
import { useGetCleave } from "@/components/GetCleave";

const LINKS = [
  ["Problem", "#problem"],
  ["Product", "#product"],
  ["Why Cleave", "#why"],
  ["Security", "#security"],
  ["FAQ", "#faq"],
] as const;

export function Nav() {
  const [open, setOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const { getCleave } = useGetCleave();
  const { user, signOut } = useAuth();

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 8);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <header className="sticky top-0 z-50 px-3 pt-3 sm:px-6">
      <nav
        aria-label="Main"
        className={cn(
          "mx-auto flex h-14 max-w-7xl items-center justify-between rounded-full pl-5 pr-2 transition-all duration-300",
          scrolled || open ? "bg-paper/80 shadow-[0_1px_0_rgb(12_12_12/0.08),0_8px_30px_-12px_rgb(12_12_12/0.25)] backdrop-blur-xl" : "",
        )}
      >
        <a href="#top" className="flex items-center gap-2 font-display text-xl font-extrabold tracking-tight">
          <Mark className="size-7" arrow="#ff3b2f" />
          Cleave
        </a>

        <ul className="hidden items-center gap-1 md:flex">
          {LINKS.map(([label, href]) => (
            <li key={href}>
              <a href={href} className="rounded-full px-3.5 py-2 text-[15px] text-mute transition-colors hover:bg-ink/5 hover:text-ink">
                {label}
              </a>
            </li>
          ))}
        </ul>

        <div className="hidden items-center gap-1.5 md:flex">
          <a
            href={REPO}
            aria-label="Cleave on GitHub"
            className="inline-flex size-11 items-center justify-center rounded-full text-ink transition-colors hover:bg-ink/5"
          >
            <GithubMark className="size-5" />
          </a>
          {user && (
            <div className="flex items-center gap-1 pl-1">
              <span className="max-w-[150px] truncate font-mono text-[13px] text-mute" title={user.email ?? ""}>
                {user.email}
              </span>
              <button
                onClick={() => void signOut()}
                className="rounded-full px-3 py-2 text-[13px] text-mute transition-colors hover:bg-ink/5 hover:text-ink"
              >
                Sign out
              </button>
            </div>
          )}
          <Button onClick={getCleave} className="min-h-10 px-5 text-sm">
            Get Cleave
          </Button>
        </div>

        <button
          type="button"
          className="inline-flex size-11 cursor-pointer items-center justify-center rounded-full md:hidden"
          aria-expanded={open}
          aria-controls="mobile-nav"
          aria-label={open ? "Close menu" : "Open menu"}
          onClick={() => setOpen((v) => !v)}
        >
          {open ? <X className="size-5" /> : <Menu className="size-5" />}
        </button>
      </nav>

      {open && (
        <div id="mobile-nav" className="mx-auto mt-2 max-w-7xl rounded-3xl bg-ink p-5 text-paper md:hidden">
          <ul>
            {LINKS.map(([label, href]) => (
              <li key={href}>
                <a href={href} onClick={() => setOpen(false)} className="display block py-2.5 text-3xl">
                  {label}
                </a>
              </li>
            ))}
          </ul>
          <Button onClick={() => { setOpen(false); getCleave(); }} variant="lime" className="mt-4 w-full">
            Get Cleave
          </Button>
          {user && (
            <button
              onClick={() => { setOpen(false); void signOut(); }}
              className="mt-3 w-full rounded-full py-2.5 text-center text-[14px] text-paper/70 hover:text-paper"
            >
              Sign out ({user.email})
            </button>
          )}
        </div>
      )}
    </header>
  );
}
