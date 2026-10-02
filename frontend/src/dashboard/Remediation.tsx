import { useEffect, useState } from "react";
import { getRemediation, openRemediationPr, type Remediation as Rem, type RemediationFix } from "./api";

export function Remediation() {
  const [data, setData] = useState<Rem | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getRemediation()
      .then(setData)
      .catch((e) => setError(String(e)))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="mono p-10 text-[13px] text-[color:var(--muted)]">Loading…</div>;
  if (error || !data)
    return <div className="mono p-10 text-[13px] text-[color:var(--muted)]">No remediation available. {error}</div>;

  const { fixes, templated, guidance, files } = data;

  function downloadAll() {
    for (const [name, content] of Object.entries(files)) {
      const url = URL.createObjectURL(new Blob([content], { type: "text/plain" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = name;
      a.click();
      URL.revokeObjectURL(url);
    }
  }

  return (
    <div className="mx-auto max-w-[1180px] px-6 py-10 sm:px-8">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="display text-[32px] leading-tight sm:text-[40px]">The fix, as code.</h1>
          <p className="mt-3 max-w-[640px] text-[15px] text-[color:var(--muted)]">
            {templated} change{templated === 1 ? "" : "s"} Cleave can generate as Terraform
            {guidance > 0 ? `, and ${guidance} that need a manual judgement` : ""}. Review each one,
            run <span className="mono">terraform plan</span>, apply, then rescan — Cleave never changes
            your account itself.
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={downloadAll}
            disabled={templated === 0}
            className="mono rounded-md bg-[color:var(--accent)] px-4 py-2 text-[12px] text-[color:var(--accent-ink)] disabled:opacity-40"
          >
            Download .tf bundle
          </button>
          <PrButton />
        </div>
      </div>

      {fixes.length === 0 && (
        <p className="mono mt-10 text-[13px] text-[color:var(--muted)]">
          No attack paths — nothing to remediate.
        </p>
      )}

      <div className="mt-10 space-y-4">
        {fixes.map((f, i) => (
          <FixCard key={i} fix={f} />
        ))}
      </div>
    </div>
  );
}

function FixCard({ fix }: { fix: RemediationFix }) {
  const [copied, setCopied] = useState(false);
  const templated = fix.confidence === "templated";

  function copy() {
    if (fix.terraform) {
      navigator.clipboard.writeText(fix.terraform);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }
  }

  return (
    <div
      className={`rounded-xl border p-5 ${
        templated ? "border-[color:var(--line)]" : "border-dashed border-[color:var(--line)]"
      }`}
    >
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-[260px] flex-1">
          <div className="flex items-center gap-2">
            <span
              className={`mono rounded-full px-2 py-0.5 text-[10px] ${
                templated
                  ? "bg-[color:var(--accent)]/15 accent"
                  : "border border-[color:var(--line)] text-[color:var(--dim)]"
              }`}
            >
              {templated ? "terraform" : "manual"}
            </span>
            <span className="text-[15px] text-[color:var(--text)]">{fix.title}</span>
          </div>
          <div className="mono mt-1 text-[11px] text-[color:var(--dim)]">
            cuts {fix.rel} · {fix.target}
          </div>
        </div>
        {templated && (
          <button
            onClick={copy}
            className="mono rounded-md border border-[color:var(--line)] px-3 py-1.5 text-[11px] text-[color:var(--text-2)] hover:border-[color:var(--accent)]"
          >
            {copied ? "copied" : "copy"}
          </button>
        )}
      </div>

      <p className="mt-3 text-[13px] text-[color:var(--text-2)]">{fix.note}</p>
      <p className="mt-2 text-[12px] text-[color:var(--muted)]">
        <span className="accent">might break:</span> {fix.impact}
      </p>

      {templated && fix.terraform && (
        <pre className="mono mt-4 overflow-x-auto rounded-lg border border-[color:var(--line)] bg-[color:var(--panel)] p-4 text-[11.5px] leading-relaxed text-[color:var(--text-2)]">
          {fix.terraform}
        </pre>
      )}
    </div>
  );
}

function PrButton() {
  const [state, setState] = useState<"idle" | "opening" | "done" | "error">("idle");
  const [msg, setMsg] = useState<string | null>(null);
  const [url, setUrl] = useState<string | null>(null);

  async function open() {
    setState("opening");
    const r = await openRemediationPr(false);
    if (r.ok && r.pr_url) {
      setUrl(r.pr_url);
      setState("done");
    } else {
      setMsg(r.detail ?? "PR failed");
      setState("error");
    }
  }

  if (state === "done" && url)
    return (
      <a
        href={url}
        target="_blank"
        rel="noreferrer"
        className="mono rounded-md border border-[color:var(--accent)] px-4 py-2 text-[12px] accent"
      >
        PR opened ↗
      </a>
    );

  return (
    <div className="relative">
      <button
        onClick={open}
        disabled={state === "opening"}
        className="mono rounded-md border border-[color:var(--line)] px-4 py-2 text-[12px] text-[color:var(--text-2)] hover:border-[color:var(--accent)] disabled:opacity-40"
        title="Teams: commit the fix to your infra repo and open a pull request"
      >
        {state === "opening" ? "opening…" : "Open pull request"}
      </button>
      {state === "error" && msg && (
        <div className="absolute right-0 z-10 mt-2 w-[360px] rounded-lg border border-[color:var(--line)] bg-[color:var(--panel)] p-3 text-[11.5px] leading-relaxed text-[color:var(--muted)]">
          {msg}
        </div>
      )}
    </div>
  );
}
