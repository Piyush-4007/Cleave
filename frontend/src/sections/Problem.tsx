import { Section } from "../components/ui";

const GLOSSARY = [
  ["attack path", "A chain of individually small permissions that together lead somewhere dangerous."],
  ["iam:PassRole", "Permission to hand a role to a service. If that role is admin, the service becomes admin."],
  ["minimum cut", "The fewest edges you can remove to disconnect entry points from what you protect."],
];

export function Problem() {
  return (
    <Section id="problem" className="py-24">
      <div className="grid grid-cols-1 gap-12 lg:grid-cols-[1.55fr_1fr] lg:gap-20">
        <div>
          <h2 className="display text-[38px] leading-[1.08] sm:text-[52px]">
            Not every misconfiguration is a breach.
          </h2>
          <p className="mt-6 max-w-[54ch] text-[17px] leading-relaxed text-[color:var(--text-2)]">
            A scan of a real account returns two hundred findings as a flat list. The one that
            gets you compromised looks identical to the ones that do not. So teams cannot
            prioritise, and the exploitable holes stay open for weeks.
          </p>
          <p className="mt-5 max-w-[54ch] text-[17px] leading-relaxed text-[color:var(--text-2)]">
            A public bucket of cat photos is nothing. A public bucket holding a credentials file
            that unlocks an admin role is a total compromise. Both show up the same way, because
            the tools look at one resource at a time and never model the connections. Cleave
            models the connections.
          </p>
        </div>

        <aside className="lg:pt-3">
          <div className="mono mb-5 text-[11px] uppercase tracking-[0.22em] text-[color:var(--dim)]">
            Terms
          </div>
          <dl className="space-y-6">
            {GLOSSARY.map(([term, def]) => (
              <div key={term} className="border-l-2 border-[color:var(--accent)] pl-4">
                <dt className="mono text-[13px] text-[color:var(--text)]">{term}</dt>
                <dd className="mt-1.5 text-[14px] leading-relaxed text-[color:var(--muted)]">{def}</dd>
              </div>
            ))}
          </dl>
        </aside>
      </div>
    </Section>
  );
}
