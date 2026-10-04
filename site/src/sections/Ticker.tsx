const MOVES = [
  "iam:PassRole → lambda:CreateFunction",
  "iam:CreatePolicyVersion",
  "sts:AssumeRole chain",
  "s3:GetObject on Principal *",
  "glue:CreateJob + PassRole",
  "ec2:RunInstances + instance profile",
  "iam:SetDefaultPolicyVersion",
  "secretsmanager:GetSecretValue",
  "API Gateway route, auth NONE",
  "IMDSv1 credential theft",
  "codebuild:StartBuild + PassRole",
  "0.0.0.0/0 → :22",
];

export function Ticker() {
  const row = [...MOVES, ...MOVES];
  return (
    <div className="overflow-hidden border-y border-ink bg-lime py-4" aria-label="Attack techniques Cleave models">
      <ul className="animate-marquee flex w-max gap-10 font-mono text-sm font-medium text-ink">
        {row.map((m, i) => (
          <li key={i} className="flex items-center gap-10 whitespace-nowrap" aria-hidden={i >= MOVES.length}>
            {m}
            <span className="text-ink/40" aria-hidden>
              ✕
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}
