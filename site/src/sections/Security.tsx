import { Code2, Laptop, TriangleAlert } from "lucide-react";
import { Kicker, Reveal, Section, Title } from "@/components/primitives";

const LINES: [string, boolean][] = [
  ["Read IAM, S3, EC2, VPC, Lambda …", true],
  ["List resources and policies", true],
  ["Create anything", false],
  ["Modify anything", false],
  ["Delete anything", false],
  ["Store an access key", false],
  ["Send your data to a Cleave server", false],
];

const POINTS = [
  {
    icon: Laptop,
    title: "Local. Literally.",
    body: "The engine binds to 127.0.0.1, guarded by a fresh token every launch. There is no Cleave cloud to send anything to.",
  },
  {
    icon: Code2,
    title: "Read the code first.",
    body: "Every collector, edge rule and check is open. See exactly which AWS calls it makes before you point it at production.",
  },
  {
    icon: TriangleAlert,
    title: "Honest blind spots.",
    body: "A read-only IAM role can't see Kubernetes RBAC inside EKS. Those findings say LIMITED instead of pretending to be clean.",
  },
];

export function Security() {
  return (
    <Section id="security">
      <div className="grid gap-16 lg:grid-cols-[1fr_auto] lg:items-center">
        <div>
          <Kicker n="05">Security</Kicker>
          <Title>
            Built so you don't
            <br /> have to trust us.
          </Title>
          <p className="mt-6 max-w-xl text-lg leading-relaxed text-mute text-pretty">
            A security tool that wants admin keys to your cloud is a risk of its own. Cleave asks for the least access
            that still works: two AWS-managed read-only policies, on a role you create and can delete any time.
          </p>

          <div className="mt-12 grid gap-8 sm:grid-cols-3">
            {POINTS.map((p, i) => (
              <Reveal key={p.title} delay={i * 0.06}>
                <p.icon className="size-6" aria-hidden />
                <h3 className="mt-3 font-semibold">{p.title}</h3>
                <p className="mt-1.5 text-[15px] leading-relaxed text-mute">{p.body}</p>
              </Reveal>
            ))}
          </div>
        </div>

        <Reveal delay={0.1} className="mx-auto w-full max-w-sm lg:mx-0">
          <Receipt />
        </Reveal>
      </div>
    </Section>
  );
}

function Receipt() {
  return (
    <div className="relative -rotate-2 bg-white px-7 pb-12 pt-10 font-mono text-[13px] shadow-[0_30px_60px_-30px_rgb(12_12_12/0.45)] transition-transform duration-300 hover:rotate-0">
      <span
        aria-hidden
        className="absolute inset-x-0 top-0 h-2"
        style={{ background: "radial-gradient(circle at 50% 0, #f2f0eb 6px, transparent 6.5px) 0 0 / 14px 8px repeat-x" }}
      />
      <span
        aria-hidden
        className="absolute inset-x-0 bottom-0 h-2"
        style={{ background: "radial-gradient(circle at 50% 100%, #f2f0eb 6px, transparent 6.5px) 0 0 / 14px 8px repeat-x" }}
      />
      <div className="text-center">
        <div className="font-display text-2xl font-extrabold tracking-tight">CLEAVE</div>
        <div className="mt-1 text-[11px] uppercase tracking-[0.2em] text-mute">access receipt</div>
      </div>
      <div className="mt-5 flex justify-between text-[11px] text-mute">
        <span>role: CleaveAudit</span>
        <span>#000001</span>
      </div>
      <div className="my-4 border-t-2 border-dashed border-line" />
      <div className="text-[11px] text-mute">
        SecurityAudit
        <br />
        ViewOnlyAccess
      </div>
      <div className="my-4 border-t-2 border-dashed border-line" />
      <ul className="space-y-2.5">
        {LINES.map(([l, ok]) => (
          <li key={l} className="flex justify-between gap-4">
            <span className={ok ? "text-ink" : "text-mute line-through decoration-cut/70"}>{l}</span>
            <span className={ok ? "font-semibold text-ink" : "font-semibold text-cut"} aria-label={ok ? "allowed" : "not allowed"}>
              {ok ? "YES" : "NO"}
            </span>
          </li>
        ))}
      </ul>
      <div className="my-4 border-t-2 border-dashed border-line" />
      <div className="flex justify-between text-base font-semibold">
        <span>TOTAL ACCESS</span>
        <span className="bg-lime px-1">READ-ONLY</span>
      </div>
      <div aria-hidden className="mt-6 flex h-10 items-stretch justify-center gap-[3px]">
        {Array.from({ length: 34 }, (_, i) => (
          <span key={i} className="bg-ink" style={{ width: [1, 2, 1, 3, 1, 2][(i * 5) % 6] }} />
        ))}
      </div>
      <div className="mt-2 text-center text-[10px] text-mute">no keys were harmed in this scan</div>
    </div>
  );
}
