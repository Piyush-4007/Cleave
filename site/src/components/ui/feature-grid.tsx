// Adapted from 21st.dev "Feature Grid Spotlight Cards" (Feature 08, Hirael,
// MIT (c) Mohammad Shehadeh). Changes: content is passed in, Badge dropped, titles
// use our mono display face, one card can be flagged as the highlighted one.
import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

export type Feature = { icon: LucideIcon; title: string; description: string; tag?: string; highlight?: boolean };

/** Corner crosshair, drawn half outside the card edge like a survey mark. */
const CrossDecor = ({ position }: { position: "top-start" | "bottom-end" }) => (
  <svg
    aria-hidden
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="1"
    strokeLinecap="round"
    className={cn(
      "pointer-events-none absolute z-10 size-3.5 shrink-0 text-muted-foreground",
      position === "top-start" && "start-0 top-0 -translate-x-1/2 -translate-y-1/2",
      position === "bottom-end" && "bottom-0 end-0 translate-x-1/2 translate-y-1/2",
    )}
  >
    <path d="M5 12h14" />
    <path d="M12 5v14" />
  </svg>
);

const FeatureCard = ({ className, children, ...props }: React.ComponentProps<"div">) => {
  const handlePointerMove = (e: React.PointerEvent<HTMLDivElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    e.currentTarget.style.setProperty("--mx", `${e.clientX - rect.left}px`);
    e.currentTarget.style.setProperty("--my", `${e.clientY - rect.top}px`);
  };

  return (
    <div
      onPointerMove={handlePointerMove}
      className={cn(
        "group relative flex h-full flex-col justify-start gap-6 bg-background px-6 pb-6 pt-8",
        "bg-[radial-gradient(50%_80%_at_25%_0%,var(--warm-glow),transparent)]",
        className,
      )}
      {...props}
    >
      {/* Pointer-follow spotlight, fades in on hover along --mx/--my. */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-0 transition-opacity duration-300 group-hover:opacity-100 bg-[radial-gradient(circle_200px_at_var(--mx)_var(--my),color-mix(in_oklch,var(--color-warm)_14%,transparent),transparent_70%)]"
      />
      <div className="absolute -inset-y-4 -start-px w-px bg-border" />
      <div className="absolute -inset-y-4 -end-px w-px bg-border" />
      <div className="absolute -inset-x-4 -top-px h-px bg-border" />
      <div className="absolute -inset-x-4 -bottom-px h-px bg-border" />
      {children}
    </div>
  );
};

export function FeatureGrid({ features }: { features: Feature[] }) {
  return (
    <div className="mx-auto grid w-full max-w-6xl grid-cols-1 gap-8 md:grid-cols-2 lg:grid-cols-3">
      {features.map((feature) => (
        <FeatureCard key={feature.title}>
          <CrossDecor position="top-start" />
          <CrossDecor position="bottom-end" />
          <div className="relative z-10 flex items-center justify-between">
            <div
              className={cn(
                "flex w-fit items-center justify-center rounded-xs border border-border bg-muted/20 p-3 transition-colors duration-300 group-hover:border-warm/40",
                feature.highlight && "border-cut/50",
              )}
            >
              <feature.icon aria-hidden className={cn("size-5 stroke-[1.5]", feature.highlight ? "text-cut" : "text-foreground")} />
            </div>
            {feature.tag && (
              <span className="font-mono text-[11px] uppercase tracking-[0.12em] text-muted-foreground">{feature.tag}</span>
            )}
          </div>
          <div className="relative z-10 flex flex-col gap-2">
            <h3 className="font-mono text-base font-semibold text-foreground">{feature.title}</h3>
            <p className="text-[15px] leading-relaxed text-muted-foreground">{feature.description}</p>
          </div>
        </FeatureCard>
      ))}
    </div>
  );
}
