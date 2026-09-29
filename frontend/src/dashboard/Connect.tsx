import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Copy, Check, ShieldCheck, ArrowRight } from "@phosphor-icons/react";

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
  const [copied, setCopied] = useState(false);
  const [arn, setArn] = useState("");
  const valid = ARN_RE.test(arn.trim());

  const copy = () => {
    navigator.clipboard?.writeText(SNIPPET).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    });
  };

  return (
    <div className="mx-auto max-w-[820px] px-6 py-12 sm:px-8">
      <div className="mono text-[12px] uppercase tracking-[0.16em] text-[color:var(--dim)]">First run</div>
      <h1 className="display mt-3 text-[34px] leading-tight sm:text-[44px]">Connect an AWS account.</h1>
      <p className="mt-4 max-w-[58ch] text-[16px] leading-relaxed text-[color:var(--text-2)]">
        You create a read-only role in your own account and paste back its ARN. Cleave never
        asks for an access key, and your account never leaves this machine.
      </p>

      <ol className="mt-10 space-y-8">
        <li>
          <div className="flex items-center gap-3">
            <Step n={1} />
            <h2 className="text-[17px] font-semibold text-[color:var(--text)]">Create the role in your account</h2>
          </div>
          <div className="relative mt-4 rounded-lg border border-[color:var(--line)] bg-[color:var(--panel)]">
            <button
              onClick={copy}
              className="mono absolute right-3 top-3 inline-flex items-center gap-1.5 rounded-md border border-[color:var(--line)] bg-[color:var(--bg)] px-2.5 py-1.5 text-[11px] text-[color:var(--muted)] hover:text-[color:var(--text)]"
            >
              {copied ? <Check size={13} /> : <Copy size={13} />} {copied ? "copied" : "copy"}
            </button>
            <pre className="mono overflow-x-auto p-4 text-[12px] leading-relaxed text-[color:var(--text-2)]">{SNIPPET}</pre>
          </div>
        </li>

        <li>
          <div className="flex items-center gap-3">
            <Step n={2} />
            <h2 className="text-[17px] font-semibold text-[color:var(--text)]">Paste the role ARN</h2>
          </div>
          <input
            value={arn}
            onChange={(e) => setArn(e.target.value)}
            placeholder="arn:aws:iam::123456789012:role/CleaveAudit"
            spellCheck={false}
            className="mono mt-4 w-full rounded-lg border border-[color:var(--line)] bg-[color:var(--bg)] px-4 py-3 text-[13px] text-[color:var(--text)] outline-none placeholder:text-[color:var(--dim)] focus:border-[color:var(--accent)]"
          />
          {arn && !valid && (
            <p className="mono mt-2 text-[12px] cut">that does not look like an IAM role ARN.</p>
          )}
        </li>

        <li>
          <div className="flex items-center gap-3">
            <Step n={3} />
            <h2 className="text-[17px] font-semibold text-[color:var(--text)]">Scan</h2>
          </div>
          <button
            disabled={!valid}
            onClick={() => nav("/dashboard")}
            className="mt-4 inline-flex items-center gap-2 rounded-md bg-[color:var(--accent)] px-5 py-2.5 text-[14px] font-medium text-[color:var(--accent-ink)] transition-opacity disabled:opacity-40"
          >
            Start scan <ArrowRight size={15} />
          </button>
        </li>
      </ol>

      <div className="mono mt-12 flex items-center gap-2 rounded-lg border border-[color:var(--line)] bg-[color:var(--panel)]/50 px-4 py-3 text-[12px] text-[color:var(--muted)]">
        <ShieldCheck size={16} className="accent shrink-0" weight="fill" />
        Read-only: SecurityAudit + ViewOnlyAccess. No write access, no keys, nothing uploaded.
      </div>
    </div>
  );
}

function Step({ n }: { n: number }) {
  return (
    <span className="mono grid h-7 w-7 shrink-0 place-items-center rounded-full border border-[color:var(--accent)] text-[13px] accent">
      {n}
    </span>
  );
}
