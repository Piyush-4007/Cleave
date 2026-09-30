import { useState, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { Copy, Check, ShieldCheck, ArrowRight, ArrowLeft, ArrowClockwise, CircleNotch, Cloud, Lock, Warning, SignOut } from "@phosphor-icons/react";
import { connect, disconnect, getHistory, type Analysis } from "./api";
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

function when(iso: string): string {
  return new Date(iso).toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[130px_1fr] gap-4 border-t border-[color:var(--line)] py-3 first:border-t-0 sm:grid-cols-[160px_1fr]">
      <dt className="mono text-[11.5px] uppercase tracking-[0.12em] text-[color:var(--dim)]">{label}</dt>
      <dd className="min-w-0 break-words text-[14px] text-[color:var(--text)]">{children}</dd>
    </div>
  );
}

/** Once an account is connected, this replaces the connect form: who, which account,
 *  how, and when, so there is no doubt it is connected. The form is one click away. */
function AccountCard({ data, busy, onRescan, onSwitch, onDisconnect }: {
  data: Analysis; busy: boolean; onRescan: () => void; onSwitch: () => void; onDisconnect: () => void;
}) {
  const s = data.scan!;
  const who = s.principal_type === "root" ? "root account" : s.principal_name ?? "unknown identity";
  const kind = s.principal_type === "role" ? "IAM role" : s.principal_type === "user" ? "IAM user" : "";
  const n = data.summary.paths_found;
  return (
    <div className="mt-9 rounded-xl border border-[color:var(--line)] bg-[color:var(--panel)] p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="mono inline-flex items-center gap-2 text-[12px] uppercase tracking-[0.14em] text-[color:var(--accent)]">
          <span className="h-2 w-2 rounded-full bg-[color:var(--accent)]" /> connected
        </div>
        <div className="flex gap-2">
          <button onClick={onRescan} disabled={busy}
            className="mono inline-flex items-center gap-2 rounded-md border border-[color:var(--accent)] px-3.5 py-1.5 text-[12px] text-[color:var(--text)] disabled:opacity-60">
            {busy ? <CircleNotch size={13} className="animate-spin" /> : <ArrowClockwise size={13} />}
            {busy ? "scanning…" : "rescan"}
          </button>
          <button onClick={onSwitch} disabled={busy}
            className="mono inline-flex items-center gap-2 rounded-md border border-[color:var(--line)] px-3.5 py-1.5 text-[12px] text-[color:var(--text-2)] hover:border-[color:var(--accent)] disabled:opacity-60">
            switch account <ArrowRight size={13} />
          </button>
          <button onClick={onDisconnect} disabled={busy}
            className="mono inline-flex items-center gap-2 rounded-md border border-[color:var(--line)] px-3.5 py-1.5 text-[12px] text-[color:var(--text-2)] hover:border-[color:var(--cut)] hover:text-[color:var(--cut)] disabled:opacity-60">
            <SignOut size={13} /> disconnect
          </button>
        </div>
      </div>

      <h2 className="display mt-4 text-[28px] leading-tight">{who}</h2>
      <div className="mono mt-1 text-[12.5px] text-[color:var(--muted)]">
        {kind && <>{kind} · </>}account {data.account}{s.alias && <> ({s.alias})</>}
      </div>
      <dl className="mt-4">
        <Row label="Account ID">
          <span className="mono">{data.account}</span>
          {s.alias && <span className="text-[color:var(--muted)]"> · alias {s.alias}</span>}
        </Row>
        <Row label="Signed in as">
          {who}{kind && <span className="text-[color:var(--muted)]"> · {kind}</span>}
        </Row>
        {s.arn && <Row label="ARN"><span className="mono text-[12.5px] text-[color:var(--text-2)]">{s.arn}</span></Row>}
        <Row label="Connected via">
          {s.mode === "role"
            ? <>read-only role <span className="mono text-[12.5px] text-[color:var(--text-2)]">{s.role_arn}</span></>
            : s.mode === "login" ? "your AWS login on this machine" : "command-line scan"}
        </Row>
        <Row label="Last scan">
          {when(s.scanned_at)}
          <span className="text-[color:var(--muted)]">
            {s.resources != null && <> · {s.resources.toLocaleString()} resources</>}
            {s.duration_s != null && <> · {s.duration_s}s</>}
            {" · "}{n} attack path{n === 1 ? "" : "s"}
          </span>
        </Row>
      </dl>

      {s.admin_credentials && (
        <div className="mt-4 flex gap-3 rounded-lg border border-[color:var(--line)] bg-[color:var(--bg)] px-4 py-3 text-[13px] text-[color:var(--text-2)]">
          <Warning size={17} className="accent mt-0.5 shrink-0" weight="fill" />
          <span>
            These credentials have <b className="text-[color:var(--text)]">full admin</b> rights. Cleave only
            ever makes read calls, but connecting through a read-only role is the safer habit.
            Use <i>switch account</i> to set one up.
          </span>
        </div>
      )}
    </div>
  );
}

export function Connect() {
  const nav = useNavigate();
  const { reload, data } = useAnalysis();
  const [switching, setSwitching] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [forgetHistory, setForgetHistory] = useState(false);
  const [historyCount, setHistoryCount] = useState(0);

  const askDisconnect = async () => {
    setHistoryCount((await getHistory(data?.account)).length);
    setForgetHistory(false);
    setConfirming(true);
  };
  const doDisconnect = async () => {
    setError(null);
    try {
      await disconnect(forgetHistory);
      setConfirming(false);
      setSwitching(false);
      reload();
      nav("/dashboard/connect", { replace: true });
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
    }
  };
  const [busy, setBusy] = useState<"login" | "role" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showRole, setShowRole] = useState(false);
  const [copied, setCopied] = useState(false);
  const [arn, setArn] = useState("");
  const valid = ARN_RE.test(arn.trim());

  const doConnect = async (mode: "login" | "role", roleArn?: string) => {
    setBusy(mode);
    setError(null);
    try {
      await connect(mode, mode === "role" ? (roleArn ?? arn.trim()) : undefined);
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

  const connected = !!data?.scan && data.source !== "mock";
  const rescan = () => {
    const sc = data!.scan!;
    if (sc.mode === "role" && sc.role_arn) doConnect("role", sc.role_arn);
    else if (sc.mode === "login") doConnect("login");
    else setSwitching(true); // a command-line scan: choose how to connect
  };

  if (connected && !switching) {
    return (
      <div className="mx-auto max-w-[760px] px-6 py-14 sm:px-8">
        <div className="mono text-[12px] uppercase tracking-[0.16em] text-[color:var(--dim)]">Account</div>
        <h1 className="display mt-3 text-[34px] leading-tight sm:text-[44px]">Connected.</h1>
        <p className="mt-4 max-w-[56ch] text-[16px] leading-relaxed text-[color:var(--text-2)]">
          Everything in this dashboard comes from the scan below. Rescan to refresh it.
        </p>
        <AccountCard data={data!} busy={busy !== null} onRescan={rescan} onSwitch={() => setSwitching(true)}
          onDisconnect={askDisconnect} />
        {confirming && (
          <div className="mt-4 rounded-xl border border-[color:var(--cut)]/50 bg-[color:var(--panel)] p-5">
            <div className="text-[15px] font-semibold text-[color:var(--text)]">
              Disconnect {data!.scan!.alias || data!.account}?
            </div>
            <p className="mt-2 text-[14px] leading-relaxed text-[color:var(--text-2)]">
              Cleave never stored your AWS credentials, so there is nothing to revoke. This clears
              the current scan from this machine and returns to the connect screen. Your AWS login
              itself is untouched.
            </p>
            <label className="mt-4 flex items-center gap-2.5 text-[14px] text-[color:var(--text-2)]">
              <input type="checkbox" checked={forgetHistory} onChange={(e) => setForgetHistory(e.target.checked)}
                disabled={historyCount === 0} className="accent-[color:var(--cut)]" />
              Also delete this account's scan history
              <span className="mono text-[12px] text-[color:var(--dim)]">({historyCount} stored scan{historyCount === 1 ? "" : "s"})</span>
            </label>
            <div className="mt-5 flex gap-2">
              <button onClick={doDisconnect}
                className="mono inline-flex items-center gap-2 rounded-md bg-[color:var(--cut)] px-4 py-2 text-[12px] font-medium text-white">
                <SignOut size={13} /> disconnect
              </button>
              <button onClick={() => setConfirming(false)}
                className="mono rounded-md border border-[color:var(--line)] px-4 py-2 text-[12px] text-[color:var(--text-2)]">
                cancel
              </button>
            </div>
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

  return (
    <div className="mx-auto max-w-[760px] px-6 py-14 sm:px-8">
      {connected && (
        <button onClick={() => setSwitching(false)}
          className="mono mb-6 inline-flex items-center gap-2 text-[12.5px] text-[color:var(--muted)] hover:text-[color:var(--text)]">
          <ArrowLeft size={13} /> back to {data!.scan!.alias || data!.account}
        </button>
      )}
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
