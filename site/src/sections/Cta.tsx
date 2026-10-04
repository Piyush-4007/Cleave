import { useState } from "react";
import { ArrowUpRight, Check, Copy, Download } from "lucide-react";
import { Button, GithubMark, Mark, REPO } from "@/components/primitives";
import { useGetCleave } from "@/components/GetCleave";

const CMD = ["git clone https://github.com/Piyush-4007/Cleave", "cd Cleave && cp .env.example .env", "docker compose up"];

export function Cta() {
  const [copied, setCopied] = useState(false);
  const { getCleave } = useGetCleave();
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(CMD.join("\n"));
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {
      /* clipboard blocked; text stays selectable */
    }
  };

  return (
    <section id="start" className="px-3 pb-3 sm:px-4 sm:pb-4">
      <div className="relative overflow-hidden rounded-[36px] bg-ink px-5 pb-0 pt-20 text-paper sm:px-10 md:pt-28">
        <div aria-hidden className="dots-dark absolute inset-0" />
        <div className="relative mx-auto max-w-7xl">
          <div className="grid gap-14 lg:grid-cols-[1.1fr_0.9fr] lg:items-end [&>*]:min-w-0">
            <div>
              <div className="font-mono text-xs uppercase tracking-[0.14em] text-lime">Get started · free · open source</div>
              <h2 className="display mt-6 text-[clamp(48px,8vw,112px)] text-balance">
                Your first path is <span className="text-lime">14 seconds</span> away.
              </h2>
              <div className="mt-10 flex flex-wrap gap-3">
                <Button onClick={getCleave} variant="lime">
                  <Download className="size-4" /> Download for Windows
                </Button>
                <Button href={REPO} variant="outline-dark">
                  <GithubMark className="size-4" /> View on GitHub <ArrowUpRight className="size-4" aria-hidden />
                </Button>
              </div>
            </div>

            <div className="rounded-3xl border border-white/10 bg-ink-2">
              <div className="flex items-center justify-between border-b border-white/10 px-5 py-3">
                <div className="flex gap-1.5" aria-hidden>
                  <span className="size-3 rounded-full bg-white/15" />
                  <span className="size-3 rounded-full bg-white/15" />
                  <span className="size-3 rounded-full bg-white/15" />
                </div>
                <button
                  type="button"
                  onClick={copy}
                  aria-label={copied ? "Copied" : "Copy commands"}
                  className="inline-flex min-h-9 cursor-pointer items-center gap-1.5 rounded-full px-3 font-mono text-xs text-mute-dark transition-colors hover:bg-white/5 hover:text-paper"
                >
                  {copied ? <Check className="size-3.5 text-lime" /> : <Copy className="size-3.5" />}
                  {copied ? "copied" : "copy"}
                </button>
              </div>
              <pre className="overflow-x-auto p-5 font-mono text-[13.5px] leading-8">
                {CMD.map((l) => (
                  <div key={l}>
                    <span className="select-none text-lime">$ </span>
                    {l}
                  </div>
                ))}
                <div className="text-mute-dark"># open localhost:3000 → connect → scan</div>
              </pre>
            </div>
          </div>

          <footer className="mt-24 border-t border-white/10 pt-10">
            <div className="grid gap-10 text-sm md:grid-cols-4">
              <div className="font-display text-xl font-extrabold">
                <div className="flex items-start gap-2">
                  <Mark className="size-7 text-paper" arrow="#ff3b2f" /> Cleave
                </div>
                <a
                  href="#engine"
                  className="mt-4 inline-flex items-center gap-2 rounded-full border border-white/15 px-3 py-1.5 font-mono text-[11px] font-normal uppercase tracking-wider text-mute-dark transition-colors hover:border-white/40 hover:text-paper"
                >
                  <span className="size-1.5 rounded-full bg-lime" aria-hidden /> Powered by Severance
                </a>
              </div>
              <ul className="space-y-2 text-mute-dark">
                {[
                  ["Problem", "#problem"],
                  ["Product", "#product"],
                  ["How it works", "#how"],
                ].map(([l, h]) => (
                  <li key={l}>
                    <a className="transition-colors hover:text-lime" href={h}>
                      {l}
                    </a>
                  </li>
                ))}
              </ul>
              <ul className="space-y-2 text-mute-dark">
                {[
                  ["Why Cleave", "#why"],
                  ["Security", "#security"],
                  ["GitHub", REPO],
                ].map(([l, h]) => (
                  <li key={l}>
                    <a className="transition-colors hover:text-lime" href={h}>
                      {l}
                    </a>
                  </li>
                ))}
              </ul>
              <p className="leading-relaxed text-mute-dark">
                Piyush Singh, Ketan Bhendarkar, Ashwini Lawhale. Guide: Prof. Manoj Shinde. MIT-ADT University, Pune ·
                BCCC39. Not affiliated with AWS.
              </p>
            </div>
          </footer>

          <div
            aria-hidden
            className="display pointer-events-none mt-8 select-none text-center text-[clamp(96px,27vw,420px)] leading-[0.72] text-paper/[0.06]"
          >
            Cleave
          </div>
        </div>
      </div>
    </section>
  );
}
