import { Mark } from "../components/Logo";

export function Footer() {
  return (
    <footer className="border-t border-[color:var(--line)] py-14">
      <div className="mx-auto flex max-w-[1180px] flex-col gap-10 px-5 sm:px-8 md:flex-row md:items-start md:justify-between">
        <div className="max-w-[34ch]">
          <div className="flex items-center gap-2.5">
            <Mark size={24} accentArrow />
            <span className="display text-[18px]">Cleave</span>
          </div>
          <p className="mt-4 text-[14px] leading-relaxed text-[color:var(--muted)]">
            Reachability-ranked attack-path analysis for AWS. Open, self-hosted, deterministic.
          </p>
        </div>

        <div className="grid grid-cols-2 gap-x-12 gap-y-8 sm:grid-cols-3">
          <FooterCol title="Project" links={[["GitHub", "https://github.com/Piyush-4007/Cleave"], ["Docs", "https://github.com/Piyush-4007/Cleave"]]} />
          <FooterCol title="Learn" links={[["The problem", "#problem"], ["How it works", "#method"], ["Compare", "#compare"]]} />
          <div>
            <div className="mono mb-4 text-[11px] uppercase tracking-[0.18em] text-[color:var(--dim)]">Author</div>
            <p className="text-[13px] leading-relaxed text-[color:var(--muted)]">
              Piyush Singh.
            </p>
          </div>
        </div>
      </div>
      <div className="mx-auto mt-12 max-w-[1180px] px-5 sm:px-8">
        <div className="mono text-[11px] text-[color:var(--dim)]">Not affiliated with AWS.</div>
      </div>
    </footer>
  );
}

function FooterCol({ title, links }: { title: string; links: [string, string][] }) {
  return (
    <div>
      <div className="mono mb-4 text-[11px] uppercase tracking-[0.18em] text-[color:var(--dim)]">{title}</div>
      <ul className="space-y-3">
        {links.map(([label, href]) => (
          <li key={label}>
            <a href={href} className="text-[13px] text-[color:var(--muted)] transition-colors hover:text-[color:var(--text)]">{label}</a>
          </li>
        ))}
      </ul>
    </div>
  );
}
