import { Section, Button } from "../components/ui";

const COMMANDS = [
  ["git clone", " github.com/Piyush-4007/Cleave && cd cleave"],
  ["cp", " .env.example .env"],
  ["docker compose up", ""],
];

export function GetStarted() {
  return (
    <Section id="start" className="border-t border-[color:var(--line)] py-24">
      <div className="grid grid-cols-1 gap-12 lg:grid-cols-2 lg:gap-16">
        <div>
          <h2 className="display text-[34px] leading-tight sm:text-[44px]">
            Three commands, then paste a role ARN.
          </h2>
          <p className="mt-5 max-w-[48ch] text-[16px] leading-relaxed text-[color:var(--text-2)]">
            Cleave shows you a snippet to run in your own account. It creates the read-only role,
            you copy back its ARN, and the scan begins. No keys leave your machine.
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <Button href="https://github.com/Piyush-4007/Cleave">Read the docs</Button>
            <Button href="https://github.com/Piyush-4007/Cleave" variant="outline">View on GitHub</Button>
          </div>
        </div>

        <div className="rounded-lg border border-[color:var(--line)] bg-[color:var(--panel)] p-6">
          <div className="mono mb-4 flex items-center gap-1.5 text-[color:var(--dim)]">
            <span className="h-2.5 w-2.5 rounded-full bg-[color:var(--line)]" />
            <span className="h-2.5 w-2.5 rounded-full bg-[color:var(--line)]" />
            <span className="h-2.5 w-2.5 rounded-full bg-[color:var(--line)]" />
            <span className="ml-2 text-[11px]">install</span>
          </div>
          <pre className="mono overflow-x-auto text-[13px] leading-[2]">
            {COMMANDS.map(([cmd, rest], i) => (
              <div key={i}>
                <span className="text-[color:var(--dim)]">$ </span>
                <span className="accent">{cmd}</span>
                <span className="text-[color:var(--text-2)]">{rest}</span>
              </div>
            ))}
            <div className="mt-3 text-[color:var(--muted)]"># open localhost:3000 and connect your account</div>
          </pre>
        </div>
      </div>
    </Section>
  );
}
