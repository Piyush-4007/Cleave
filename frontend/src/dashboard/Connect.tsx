import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Copy, Check, ShieldCheck, ArrowRight, CircleNotch, Cloud, Lock } from "@phosphor-icons/react";
import { connect } from "./api";
import { useAnalysis } from "./useAnalysis";

const SNIPPET = `# Run in your own AWS account. Creates a read-only role Cleave assumes.
resource "aws_iam_role" "cleave_audit" {
  name = "CleaveAudit"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { AWS = "YOUR_ADMIN_ARN" }, Action = "sts:AssumeRole" }]
  })
  managed_policy_arns = [
    "arn:aws:iam::aws:policy/SecurityAudit",
    "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess",
  ]
}
output "role_arn" { value = aws_iam_role.cleave_audit.arn }`;

const ARN_RE = /^arn:aws:iam::\d{12}:role\/.+/;

export function Connect() {
  const nav = useNavigate();
  const { reload } = useAnalysis();
  const [busy, setBusy] = useState<"login" | "role" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showRole, setShowRole] = useState(false);
  const [copied, setCopied] = useState(false);
  const [arn, setArn] = useState("");
  const valid = ARN_RE.test(arn.trim());

  const doConnect = async (mode: "login" | "role") => {
    setBusy(mode);
    setError(null);
    try {
      await connect(mode, mode === "role" ? arn.trim() : undefined);
      reload();
      nav("/dashboard");
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
      setBusy(null);
    }
  };

  const copy = () => {
    navigator.clipboard?.writeText(SNIPPET).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    });
  };

  return (
    <div className="mx-auto max-w-[760px] px-6 py-14 sm:px-8">
      <div className="mono text-[12px] uppercase tracking-[0.16em] text-[color:var(--dim)]">Connect</div>
      <h1 className="display mt-3 text-[34px] leading-tight sm:text-[44px]">Connect an AWS account.</h1>
      <p className="mt-4 max-w-[56ch] text-[16px] leading-relaxed text-[color:var(--text-2)]">
        Read-only, and local-first: nothing leaves this machine, and Cleave only ever makes
        read calls.
      </p>

      {/* primary: use my login */}
      <button
        onClick={() => doConnect("login")}
        disabled={busy !== null}
        className="mt-9 flex w-full items-center gap-4 rounded-xl border border-[color:var(--accent)]/50 bg-[color:var(--panel)] p-5 text-left transition-colors hover:border-[color:var(--accent)] disabled:opacity-60"
      >
        <span className="grid h-11 w-11 shrink-0 place-items-center rounded-lg bg-[color:var(--accent)] text-[color:var(--accent-ink)]">
          {busy === "login" ? <CircleNotch size={20} className="animate-spin" /> : <Cloud size={20} weight="fill" />}
        </span>
        <span className="min-w-0 flex-1">
          <span className="block text-[16px] font-semibold text-[color:var(--text)]">
            {busy === "login" ? "Scanning your account…" : "Connect with my AWS login"}
          </span>
          <span className="mono mt-0.5 block text-[12.5px] text-[color:var(--muted)]">
            uses the AWS credentials already on this machine · one click
          </span>
        </span>
        {busy !== "login" && <ArrowRight size={18} className="shrink-0 text-[color:var(--muted)]" />}
      </button>

      {/* advanced: read-only role */}
      <button
        onClick={() => setShowRole((s) => !s)}
        className="mono mt-4 flex items-center gap-2 text-[13px] text-[color:var(--muted)] hover:text-[color:var(--text)]"
      >
        <Lock size={14} /> or use a scoped read-only role {showRole ? "−" : "+"}
      </button>

      {showRole && (
        <div className="mt-4 rounded-xl border border-[color:var(--line)] p-5">
          <p className="text-[14px] text-[color:var(--text-2)]">
            More locked down: create a role Cleave assumes, so it never uses your own
            credentials. Run this in your account, then paste the role ARN.
          </p>
          <div className="relative mt-4 rounded-lg border border-[color:var(--line)] bg-[color:var(--panel)]">
            <button
              onClick={copy}
              className="mono absolute right-3 top-3 inline-flex items-center gap-1.5 rounded-md border border-[color:var(--line)] bg-[color:var(--bg)] px-2.5 py-1.5 text-[11px] text-[color:var(--muted)] hover:text-[color:var(--text)]"
            >
              {copied ? <Check size={13} /> : <Copy size={13} />} {copied ? "copied" : "copy"}
            </button>
            <pre className="mono overflow-x-auto p-4 text-[12px] leading-relaxed text-[color:var(--text-2)]">{SNIPPET}</pre>
          </div>
          <input
            value={arn}
            onChange={(e) => setArn(e.target.value)}
            placeholder="arn:aws:iam::123456789012:role/CleaveAudit"
            spellCheck={false}
            className="mono mt-4 w-full rounded-lg border border-[color:var(--line)] bg-[color:var(--bg)] px-4 py-3 text-[13px] text-[color:var(--text)] outline-none placeholder:text-[color:var(--dim)] focus:border-[color:var(--accent)]"
          />
          <button
            onClick={() => doConnect("role")}
            disabled={!valid || busy !== null}
            className="mt-4 inline-flex items-center gap-2 rounded-md bg-[color:var(--accent)] px-5 py-2.5 text-[14px] font-medium text-[color:var(--accent-ink)] transition-opacity disabled:opacity-40"
          >
            {busy === "role" ? <><CircleNotch size={15} className="animate-spin" /> Scanning…</> : <>Connect with role <ArrowRight size={15} /></>}
          </button>
        </div>
      )}

      {error && (
        <div className="mono mt-5 rounded-lg border border-[color:var(--cut)]/40 bg-[color:var(--cut)]/8 px-4 py-3 text-[12.5px] cut">
          {error}
        </div>
      )}

      <div className="mono mt-12 flex items-center gap-2 rounded-lg border border-[color:var(--line)] bg-[color:var(--panel)]/50 px-4 py-3 text-[12px] text-[color:var(--muted)]">
        <ShieldCheck size={16} className="accent shrink-0" weight="fill" />
        Read-only. No write access, no keys stored, nothing uploaded.
      </div>
    </div>
  );
}
