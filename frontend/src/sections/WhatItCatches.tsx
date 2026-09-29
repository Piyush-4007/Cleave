import { Scissors, TrendUp, Key, Database } from "@phosphor-icons/react";
import { Section } from "../components/ui";

export function WhatItCatches() {
  return (
    <Section className="py-24">
      <h2 className="display mb-12 text-[32px] leading-tight sm:text-[40px]">What it catches.</h2>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        {/* wide: the headline feature, with its own visual */}
        <article className="relative overflow-hidden rounded-xl border border-[color:var(--accent)]/40 bg-[color:var(--panel)] p-7 md:col-span-2">
          <Scissors size={24} className="accent" />
          <h3 className="display mt-4 text-[24px]">The minimum cut</h3>
          <p className="mt-2 max-w-[46ch] text-[15px] leading-relaxed text-[color:var(--text-2)]">
            Not another list. The single smallest change that breaks the most attack paths, with
            its disruption scored, ready to become a pull request.
          </p>
          <div className="mono mt-6 flex items-baseline gap-3 text-[color:var(--muted)]">
            <span className="display text-[44px] text-[color:var(--text)]">1</span>
            <span className="accent text-[22px]">→</span>
            <span className="display text-[44px] accent">8</span>
            <span className="text-[13px]">one change, eight paths gone</span>
          </div>
        </article>

        <Feature icon={<Key size={22} />} title="Credential theft"
                 body="Read a bucket, steal a key left in a file, escalate. Validated on real AWS." />
        <Feature icon={<TrendUp size={22} />} title="Privilege escalation"
                 body="Policy rollback, PassRole, role chaining. The moves an attacker actually makes." />
        <article className="rounded-xl border border-[color:var(--line)] bg-[color:var(--panel)] p-7 md:col-span-2">
          <Database size={22} className="text-[color:var(--muted)]" />
          <h3 className="display mt-4 text-[22px]">Paths to sensitive data</h3>
          <p className="mt-2 max-w-[54ch] text-[15px] leading-relaxed text-[color:var(--text-2)]">
            Admin is not the only prize. Cleave also finds routes to the data stores you tag as
            production, so reaching a customer database counts as a finding too.
          </p>
        </article>
      </div>
    </Section>
  );
}

function Feature({ icon, title, body }: { icon: React.ReactNode; title: string; body: string }) {
  return (
    <article className="rounded-xl border border-[color:var(--line)] bg-[color:var(--panel)] p-7">
      <span className="text-[color:var(--muted)]">{icon}</span>
      <h3 className="display mt-4 text-[22px]">{title}</h3>
      <p className="mt-2 text-[15px] leading-relaxed text-[color:var(--text-2)]">{body}</p>
    </article>
  );
}
