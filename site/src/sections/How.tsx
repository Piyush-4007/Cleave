import { Kicker, Reveal, Section, Title } from "@/components/primitives";

const STEPS = [
  ["Collect", "A read-only snapshot: identities, policies, buckets, networks, functions, keys. Collectors read. They never judge."],
  ["Graph", "Resources and identities become nodes. Every permission an attacker could use becomes an edge, with its evidence."],
  ["Search", "Walk from every entry point to admin and to sensitive data. Rank by how reachable and how damaging."],
  ["Cut", "Compute the fewest edges whose removal disconnects them all, then turn each into a plain-English fix."],
];

const SERVICES =
  "IAM · S3 · EC2 · VPC · Lambda · RDS · Secrets Manager · KMS · ECS · EKS · Glue · SageMaker · CodeBuild · CloudFormation · SNS · SQS · ECR · DynamoDB · API Gateway · CloudTrail";

export function How() {
  return (
    <Section id="how" className="rounded-t-[40px] bg-ink text-paper">
      <Kicker n="03" dark>
        How it works
      </Kicker>
      <Title className="max-w-4xl">
        Four steps. <span className="text-mute-dark">No model guessing what's dangerous.</span>
      </Title>

      <div className="mt-20 grid gap-12 md:grid-cols-2 lg:grid-cols-4 lg:gap-8">
        {STEPS.map(([t, b], i) => (
          <Reveal key={t} delay={i * 0.08}>
            <div
              className="display text-[120px] leading-none text-transparent"
              style={{ WebkitTextStroke: i === 3 ? "2px #ff3b2f" : "1.5px rgb(242 240 235 / 0.35)" }}
              aria-hidden
            >
              0{i + 1}
            </div>
            <h3 className="display mt-2 text-3xl">{t}</h3>
            <p className="mt-3 leading-relaxed text-mute-dark">{b}</p>
          </Reveal>
        ))}
      </div>

      <div className="mt-20 border-t border-white/10 pt-8">
        <div className="font-mono text-xs uppercase tracking-wider text-lime">Reads today</div>
        <p className="display mt-4 text-2xl leading-snug text-paper/80 md:text-3xl">{SERVICES}</p>
      </div>
    </Section>
  );
}
