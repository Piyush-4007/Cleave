import { Desktop, Eye, Key } from "@phosphor-icons/react";
import { Section } from "../components/ui";

const POINTS = [
  { icon: <Desktop size={22} />, title: "Runs on your machine",
    body: "docker compose up, then open localhost:3000. Your account is never uploaded anywhere." },
  { icon: <Eye size={22} />, title: "Read-only by design",
    body: "A SecurityAudit and ViewOnlyAccess role you create yourself. It can look, never touch." },
  { icon: <Key size={22} />, title: "Holds no secrets",
    body: "You paste a role ARN, not a key. Cleave never asks for an access key, ever." },
];

export function Trust() {
  return (
    <Section id="trust" className="border-t border-[color:var(--line)] py-24">
      <div className="grid grid-cols-1 gap-12 lg:grid-cols-[1fr_1.7fr] lg:gap-20">
        <h2 className="display text-[32px] leading-[1.1] sm:text-[40px]">
          A security tool you would actually trust with your account.
        </h2>
        <div className="grid grid-cols-1 gap-y-8 sm:grid-cols-3 sm:gap-8">
          {POINTS.map((p) => (
            <div key={p.title}>
              <span className="accent">{p.icon}</span>
              <h3 className="mt-4 text-[16px] font-semibold text-[color:var(--text)]">{p.title}</h3>
              <p className="mt-2 text-[14px] leading-relaxed text-[color:var(--muted)]">{p.body}</p>
            </div>
          ))}
        </div>
      </div>
    </Section>
  );
}
