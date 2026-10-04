import { Reveal, Section } from "@/components/primitives";

// The "powered by" moment — like a game/hardware splash. Names the engine inside Cleave.
export function Engine() {
  return (
    <Section id="engine" className="text-center">
      <Reveal className="mx-auto max-w-3xl">
        <div className="font-mono text-xs uppercase tracking-[0.2em] text-mute">Powered by</div>

        <h2 className="relative mt-5 inline-block">
          <span className="display text-[clamp(64px,14vw,196px)] leading-[0.86]">Severance</span>
          <span aria-hidden className="absolute -bottom-1 left-0 right-0 h-[6px] -rotate-[1.2deg] bg-lime sm:h-2" />
        </h2>

        <p className="mx-auto mt-10 max-w-xl text-lg leading-relaxed text-mute text-pretty">
          The engine inside Cleave — a <span className="text-ink">deterministic, reachability-ranked attack-path
          engine</span>. It enumerates every route to admin, ranks them, and names the one cut that severs the
          most. <span className="mark text-ink">No machine learning; same input, same output, every time.</span>
        </p>

        <div className="mt-8 flex flex-wrap items-center justify-center gap-2 font-mono text-[11px] uppercase tracking-wider text-mute">
          <span className="rounded-full border border-line px-3 py-1.5">deterministic</span>
          <span className="rounded-full border border-line px-3 py-1.5">no machine learning</span>
          <span className="rounded-full border border-line px-3 py-1.5">reproducible</span>
        </div>
      </Reveal>
    </Section>
  );
}
