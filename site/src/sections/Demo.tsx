import { useEffect, useRef, useState } from "react";
import { Pause, Play, Volume2, VolumeX } from "lucide-react";
import { Reveal } from "@/components/primitives";

/*
  The teaser. Autoplays (muted, looped) the moment it scrolls into view and pauses when it
  leaves — the pattern every launch site uses. Muted is the only kind of autoplay browsers
  allow, so there's a tap-to-unmute (ours has music + SFX). Respects prefers-reduced-motion.
*/
export function Demo() {
  const ref = useRef<HTMLVideoElement>(null);
  const [muted, setMuted] = useState(true);
  const [playing, setPlaying] = useState(false);

  useEffect(() => {
    const v = ref.current;
    if (!v) return;
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const io = new IntersectionObserver(
      ([e]) => {
        if (e.isIntersecting && e.intersectionRatio >= 0.5) {
          if (!reduce) v.play().then(() => setPlaying(true)).catch(() => {});
        } else {
          v.pause();
          setPlaying(false);
        }
      },
      { threshold: [0, 0.5, 1] },
    );
    io.observe(v);
    return () => io.disconnect();
  }, []);

  const togglePlay = () => {
    const v = ref.current;
    if (!v) return;
    if (v.paused) v.play().then(() => setPlaying(true)).catch(() => {});
    else {
      v.pause();
      setPlaying(false);
    }
  };

  const toggleMute = () => {
    const v = ref.current;
    if (!v) return;
    v.muted = !v.muted;
    setMuted(v.muted);
    if (!v.muted && v.paused) v.play().then(() => setPlaying(true)).catch(() => {});
  };

  return (
    <section id="watch" className="relative px-4 py-24 sm:px-6 md:py-32">
      <div className="mx-auto w-full max-w-6xl">
        <Reveal className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <div className="flex items-center gap-2 font-mono text-xs uppercase tracking-[0.14em] text-mute">
              <span className="rounded-full bg-ink px-2 py-0.5 text-paper">▶</span>
              See it work
            </div>
            <h2 className="display mt-6 text-[40px] text-balance sm:text-5xl lg:text-[64px]">
              Twenty seconds, <span className="text-mute">start to cut.</span>
            </h2>
          </div>
          <p className="max-w-sm text-[15px] leading-relaxed text-mute text-pretty">
            A real scan: the path an attacker walks to admin, the one cut that breaks it, and how Cleave
            scores against the tools you already run.
          </p>
        </Reveal>

        <Reveal delay={0.1} className="group relative mt-12 overflow-hidden rounded-[28px] border border-line bg-ink shadow-[0_30px_80px_-30px_rgb(12_12_12/0.5)]">
          <video
            ref={ref}
            src="/cleave-demo.mp4"
            poster="/cleave-demo.jpg"
            muted={muted}
            loop
            playsInline
            preload="metadata"
            onClick={togglePlay}
            aria-label="Cleave product teaser — find the path, make the cut"
            className="block aspect-video w-full cursor-pointer"
          />

          {/* controls */}
          <div className="pointer-events-none absolute inset-x-0 bottom-0 flex items-center justify-between gap-3 bg-gradient-to-t from-ink/70 to-transparent p-4 opacity-0 transition-opacity duration-200 group-hover:opacity-100">
            <button
              type="button"
              onClick={togglePlay}
              aria-label={playing ? "Pause" : "Play"}
              className="pointer-events-auto inline-flex size-11 items-center justify-center rounded-full bg-paper/90 text-ink backdrop-blur transition-transform active:scale-95"
            >
              {playing ? <Pause className="size-5" /> : <Play className="size-5 translate-x-px" />}
            </button>
            <button
              type="button"
              onClick={toggleMute}
              aria-label={muted ? "Unmute" : "Mute"}
              className="pointer-events-auto inline-flex items-center gap-2 rounded-full bg-paper/90 px-4 py-2.5 text-sm font-semibold text-ink backdrop-blur transition-transform active:scale-95"
            >
              {muted ? <VolumeX className="size-4" /> : <Volume2 className="size-4" />}
              {muted ? "Sound" : "Mute"}
            </button>
          </div>
        </Reveal>

        <p className="mt-4 text-center font-mono text-xs text-mute">muted autoplay · tap for sound</p>
      </div>
    </section>
  );
}
