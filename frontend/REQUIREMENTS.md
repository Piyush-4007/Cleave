# Cleave — Frontend Requirements (Phase 6)

> Working spec for the two web surfaces: the **public site** and the **tool dashboard**.
> Draft for discussion — we mark it up together before any code. Nothing here is final.

---

## 0. PROJECT CONTEXT (so this doc stands on its own)

**What Cleave is.** A defensive cloud-security tool. It connects to an AWS account
**read-only**, builds a graph of every resource and identity, and finds the multi-step
**attack paths** an attacker could actually walk from an entry point (the internet, or a
leaked credential) to **admin** or to **sensitive data**. It then ranks those paths and
computes the single smallest change — the **minimum cut** — that breaks the most of them.

**The one-sentence defence (memorise):** *Free tools list findings, commercial tools
compute attack paths, and there is no open implementation of the reasoning layer in
between.*

**The thesis:** a misconfiguration is only dangerous if an attacker can *reach* it and it
*chains* into something worse. A public bucket of cat photos is nothing; a public bucket
holding a credentials file that unlocks an admin role is a total compromise. Both look
identical in existing tools. Cleave models the connections, so it can tell them apart.

**How it runs (critical for the UI shape).** Cleave is **self-hosted and local-first**:
the user runs `docker compose up` on their own machine and opens the dashboard at
`localhost:3000`. Their AWS access never leaves their computer. They never paste AWS keys —
they create a read-only role (`CleaveAudit` = SecurityAudit + ViewOnlyAccess) in their own
account and paste back its **role ARN** (Option A). This "we never see your account, we
never hold a secret" posture is a headline selling point, not a footnote.

**What's already built (the backend the UI sits on):**
- Collectors → JSON dump of the account (IAM, S3, EC2, VPC, Lambda, RDS, Secrets, KMS).
- Graph in Neo4j; IAM policy evaluator; network reachability.
- Path search: sources (EXTERNAL / ASSUMED_COMPROMISE) → sinks (ADMIN / SENSITIVE_DATA).
- Ranking (weighted score), minimum cut, best-single-fix, documented-technique detection.
- **API** (this is what the dashboard calls):
  - `GET /health`
  - `GET /analysis` — ranked paths + minimum cut + best single fix + summary counts
  - `GET /analysis/summary` — just the numbers, no path bodies
  - `GET /analysis/paths/{id}` — one path + its drawable subgraph (each edge flagged
    `on_path` and `in_cut`)

**Tech stack (locked):** React + Vite + TypeScript + Tailwind. **Cytoscape.js** for the
graph drawing. Runs in its own Docker container; ships as part of `docker compose up`.

**Design language (from the handbook):** schematic / blueprint, **not** "hacker dashboard."
Graph-paper background, navy panels, **monospace font for all AWS identifiers** (ARNs, IDs),
**red reserved** for two things only — the minimum cut and compromise/admin sinks. Calm,
technical, trustworthy. Think an engineering diagram, not a SOC war-room.

**Hard non-goals (don't build these):** multi-cloud, a chatbot, auto-remediation without
approval, runtime threat detection, compliance-report generation, a mobile app. The UI must
resist the temptation to add features instead of proving depth.

---

## PART A — THE PUBLIC SITE (the "portswigger.net")

**Purpose.** Introduce the product to a stranger, make the problem vivid, show the value,
and hand them a clean "get started." Zero AWS, zero login, nothing sensitive. Static site,
hosts free on Vercel/Netlify.

**Audience.** Security engineers, cloud/DevOps folks, and — importantly for this project —
**academic reviewers** who may not know AWS privilege-escalation deeply. Copy must make the
idea land without assuming they know what PassRole is.

### A1. Sections (top to bottom)

1. **Hero.**
   - Headline built on the contrast: *"Your cloud scan found 247 problems. Three of them
     can actually get you breached. Cleave finds those three."*
   - One-line subhead: what it is (attack-path analysis for AWS, open, runs on your machine).
   - Primary CTA: **Get started** (→ install). Secondary: **See how it works** (scrolls down).
   - Visual: a stylised version of the path graph (the star feature), not a stock photo.

2. **The problem.** Plain-language: scanners return flat lists; one critical hole looks
   identical to 246 harmless ones; teams can't prioritise, so exploitable holes stay open.
   A small before/after visual (flat list of red dots → three ranked paths).

3. **The insight / how it thinks.** The cat-photos-vs-credentials-bucket example. The idea
   that *reachability* is what makes a misconfiguration dangerous.

4. **What it catches (features).** 3–4 cards, each with a mini-diagram:
   - Privilege-escalation paths (e.g. policy-rollback, PassRole).
   - Credential-theft chains (read a bucket → steal a key → escalate).
   - The **minimum cut** — the one change that breaks the most paths (the headline).
   - Paths to sensitive data, not just admin.

5. **The path viewer, shown off.** A real screenshot/gif of the dashboard's star screen —
   a left-to-right path with the cut in red. "This is what a finding looks like in Cleave."

6. **The trust pitch.** Local-first, read-only, never sees your account, never holds a
   secret (Option A). This is the section security people will scan for.

7. **How it's different (comparison).** Short, honest table vs. free tools (Prowler,
   ScoutSuite), config linters (Checkov), and commercial (Wiz). The line: free tools list,
   commercial tools compute-but-closed, Cleave is the open reasoning layer.

8. **The research angle (for reviewers).** A short strip: deterministic (no ML, reproducible),
   the minimum-cut contribution, the pre-deployment merge gate (Sem 8), the open benchmark.

9. **Get started / install.** The three commands (`git clone` → `cp .env.example .env` →
   `docker compose up`), the connect-account (paste-the-ARN) explanation, link to docs.

10. **Footer.** Repo link, docs, author (Piyush Singh), license.

### A2. Public-site requirements checklist
- Fully responsive (phone → desktop), fast, no backend calls.
- Shares the dashboard's design tokens (same navy/mono/red system).
- Accessible (contrast, keyboard, alt text on every diagram).
- Copy pitched so a non-AWS reviewer follows it; AWS terms explained inline on first use.
- All diagrams are original (no copyrighted logos beyond fair comparison references).

---

## PART B — THE DASHBOARD (the tool itself)

**Purpose.** The real product. Runs locally. Where scanning, path-viewing, and remediation
happen. Six screens (handbook) plus a shell.

### B0. The shell (wraps every screen)
- Left nav or top bar linking the six screens.
- A persistent **scan status** indicator (last scan time, account ID, "rescan" button).
- The account being viewed (account ID in mono), and a clear "read-only" badge.
- Design: navy panels on graph-paper, mono for identifiers, generous whitespace.

### B1. Connect account *(first-run screen)*
- **Purpose:** get the user from zero to a scannable account without ever asking for keys.
- **Shows:** a generated CloudFormation/Terraform snippet they run in *their* account to
  create the `CleaveAudit` role; a field to paste back the **role ARN**; a "test connection"
  button; a "start first scan" button.
- **Never** shows an access-key/secret field. This is the Option A promise made visible.
- **States:** not-connected (default), testing, connected, error (bad ARN / can't assume).
- **Backend reality:** ⚠️ *Not built yet.* Today the role ARN lives in `.env`
  (`CLEAVE_ROLE_ARN`) and scanning is a CLI step (`./scan.sh` + `./load.sh`). Wiring a
  live "connect + scan" flow needs a small new API endpoint (trigger scan) + a way to set
  the ARN. **Decision needed** (see open questions).

### B2. Dashboard / overview *(the landing screen once connected)*
- **Purpose:** the at-a-glance posture + the contrast number that sells the whole thesis.
- **Shows:**
  - A **posture headline** — the contrast: *"X resources scanned · Y attack paths · Z on a
    live path to admin."*
  - The **top-ranked paths** (3–5), each a one-line summary with its score and technique.
  - The **best single fix** callout — "one change breaks N of M paths."
  - Sink/source breakdown (admin vs sensitive-data sinks; external vs assumed-compromise).
  - Last scan time, account ID.
- **Data:** `GET /analysis/summary` + top of `GET /analysis`. ✅ *Buildable now.*
- **Note on the "247 findings" number:** we do **not** compute a Prowler-style CIS findings
  count yet, so a literal "247 findings, 3 on a path" needs either (a) adding a findings
  baseline, or (b) rephrasing the contrast around what we do compute (resources / paths).
  **Decision needed.**

### B3. Path viewer *(THE STAR — the demo lives here)*
- **Purpose:** show one attack path as a story a human can read hop by hop, and show the cut.
- **Shows:**
  - A **left-to-right Cytoscape graph** of the path + one hop of context (never the full
    graph). Nodes = resources/identities (mono labels); edges labelled by their `reason`.
  - The **minimum cut edge(s) in red.**
  - A **hop-by-hop narration** panel (the plain-English story of the route).
  - A **node inspector**: click a node → its raw config / evidence.
  - A **remediation panel**: the fix for the cut, its disruption cost, "N of M paths broken."
  - Path metadata: score + factor breakdown (so the score is transparent), confidence
    (Certain vs Possible), the documented technique if any.
- **Data:** `GET /analysis/paths/{id}` (returns the path + subgraph with `on_path`/`in_cut`
  flags already computed). ✅ *Buildable now — the API was designed for exactly this.*
- **States:** loading, the path, an "eliminated" state (after a fix, path gone).
- This screen is what gets demoed. It must be beautiful and legible.

### B4. Findings list
- **Purpose:** the conventional flat list — but with the Cleave twist: filterable by
  **"on an attack path."** Deliberately *not* the landing screen (that's the point).
- **Shows:** a table of resources/edges/issues; a prominent filter "only show things on a
  live path"; columns for resource, type, why it matters, which path(s) it's on.
- **Data:** derivable from `GET /analysis` (the paths and their edges). ✅ *Buildable now*
  for path-based findings. A full "all findings incl. off-path" list would need the CIS/
  findings work that doesn't exist yet. **Scope decision.**

### B5. Remediation
- **Purpose:** turn the cut into action.
- **Shows:** the ranked cut candidates (best single fix + the full minimum cut), each with
  its plain-English fix, disruption cost, and paths-broken; a "verify" affordance (rescan →
  confirm the path is gone).
- **Data:** `minimum_cut` + `best_single_fix` from `GET /analysis`. ✅ *Buildable now* for
  display. The actual Terraform-patch/PR generation is **Phase 8 (Sem 8)** — for Sem 7 this
  screen *shows* the fix; it doesn't open a PR yet. **Set expectations.**

### B6. Scan history
- **Purpose:** posture (score / path count) over time.
- **Shows:** a timeline/chart of past scans and their headline numbers.
- **Backend reality:** ⚠️ *Not built.* Needs scan results persisted (Postgres is in the
  compose file but not wired). For Sem 7 this can be (a) deferred, (b) faked with seeded
  data for the demo, or (c) a small storage addition. **Decision needed.**

### B7. Cross-cutting requirements
- **Design system:** a tiny token set — navy palette, one accent, red-for-cut-only, mono
  font (JetBrains Mono / similar) for identifiers, sans for prose; spacing scale; card and
  panel components; consistent edge/confidence colour legend.
- **Component library:** path-summary card, hop-narration row, node-inspector drawer,
  score-breakdown chip, confidence badge (Certain/Possible), cut-fix card, the Cytoscape
  canvas wrapper, empty/loading/error states.
- **States everywhere:** loading, empty ("no paths found — here's what that means"),
  error (API down / graph not loaded), and the post-fix "path eliminated" state.
- **Rendering rule:** never draw the full account graph — only a path's subgraph + one hop
  (the API already enforces this).
- **Accessibility & responsiveness:** works down to a laptop screen for the demo; keyboard
  navigable; colour is never the *only* signal (the cut is red *and* labelled).
- **Mock-first build:** every screen should build against saved fixture JSON (we have
  fixtures 01–07 and the live `/analysis` output) before being wired to the live API, so UI
  work isn't blocked on backend gaps.

---

## PART C — REALITY CHECK: what's ready vs what needs backend

| Screen | Data source | Ready now? | Gap |
|---|---|---|---|
| Public site | none | ✅ | — |
| Path viewer (B3) | `/analysis/paths/{id}` | ✅ | — |
| Dashboard (B2) | `/analysis/summary` | ✅ | the "findings count" contrast number |
| Remediation display (B5) | `/analysis` | ✅ | PR generation is Phase 8 |
| Findings (B4) | `/analysis` | ✅ (path-based) | full findings list needs CIS work |
| Connect account (B1) | — | ⚠️ | needs a trigger-scan endpoint + ARN setting |
| Scan history (B6) | — | ⚠️ | needs results persisted (Postgres) |

**Implication for Sem 7:** the demo-critical path — **dashboard → path viewer → cut →
remediation** — is fully buildable on today's API. The three ⚠️ screens are either small
backend additions or can be sensibly faked/deferred for the review. We should build the
green rows first and decide the ⚠️ ones deliberately.

---

## OPEN QUESTIONS (your call — let's discuss)

1. **Build order:** public site first (locks the visual language, sharpens the pitch) or
   dashboard first (the graded piece)? *(I lean public site first.)*
2. **The contrast number:** do we add a lightweight findings/CIS-check count so the demo can
   say "247 findings, 3 on a path", or reframe the headline around resources/paths that we
   already compute honestly?
3. **Connect-account (B1):** build the live connect-and-scan flow now (small backend work),
   or ship Sem 7 with the ARN in `.env` and make B1 an explainer screen?
4. **Scan history (B6):** defer to Sem 8, fake it with seed data for the demo, or wire
   Postgres now?
5. **Remediation (B5):** are we agreed it *shows* the fix for Sem 7, with real PR generation
   landing in Phase 8?
6. **Scope of the findings screen (B4):** path-based only for now, or do we want the full
   flat list (which needs the CIS work)?
7. **Design tone:** how far toward "blueprint/schematic" vs. a warmer modern-SaaS look? The
   handbook says schematic; your call on how literal.
8. **Hosted demo:** confirm we do the Vercel (public site) + free VM (dashboard demo) split
   for the review room, plus a backup video.

---

## DESIGN DIRECTION — LOCKED 2026-09-27

**Approach: Option 1 — two design identities as themes** (from "Cleave Mockups v2").
The theme toggle swaps the *entire* design language, not just colors. **Dark is default.**
Fallback: if toggling ever feels like two different products, switch to **Option 3**
(Field manual = public site, Signal = dashboard). Piyush wants both looks live for now.

### DARK theme = "Signal" (default) — mockups 2d (landing), 2g (dashboard)
- **Fonts:** Geist (sans) + Geist Mono (identifiers).
- **Background:** `#0B0B0B`; panels `#141414`, `#2A2A2A`; hairlines `#333333`.
- **Accent (brand):** signal orange `#FF6A1A`; soft `#FF8F5A`.
- **Text:** `#F5F5F2` primary, `#C8C8C2` secondary, `#9A9A94` muted, `#6E6E68` dim.
- **⚠ Cut colour:** orange is the brand accent here, so the minimum cut needs its OWN
  treatment (don't reuse plain orange for both). Decide: a hotter red-orange for the cut,
  or keep orange = cut and pick a neutral for general accent. Resolve during build.

### LIGHT theme = "Field manual" — mockups 2b (landing), 2e (dashboard)
- **Fonts:** Newsreader (serif, display + prose) + IBM Plex Mono (identifiers).
- **Background:** warm paper `#F7F2E7`; panels `#EFE8DA`, `#ECE5D3`.
- **Accent (brand):** forest green `#2F5D46`; ink `#1F2A1F`.
- **Cut colour:** terracotta red `#C0432B` (already distinct from the green accent — good).
- **Text:** `#1F2A1F` primary, `#3E4638` / `#5A5E4C` secondary, `#8A8570` muted.
- Info/"possible" accent seen in mock: blue `#2A78D6`.

### What the chosen mockups already nail (keep these)
- **2e path viewer:** the path as a vertical transit line, narration beside each stop, raw
  policy JSON in a right-hand inspector, cut marked red. Maps 1:1 to `/analysis/paths/{id}`.
- **2g remediation:** "Fixes ranked by paths broken", best-fix card with a policy diff +
  "8/11 paths broken" + disruption, rows for the rest. Maps to `best_single_fix` +
  `minimum_cut`. Its "PR generation · Phase 8" badge correctly marks that deferral.
- **2d landing:** the "247 / 3 / 1 · findings / paths / fix" hero — the thesis in three numbers.
- **2b landing:** the margin glossary (attack path, PassRole, minimum cut) — excellent for
  non-AWS academic reviewers; keep it.

### Consequences to handle
- **Logo (next task):** must read in BOTH forest green and signal orange — design a neutral
  mark that takes the theme accent, not a colour-baked logo.
- **Two font pairs load** (Geist + Geist Mono; Newsreader + Plex Mono) — self-host, subset,
  lazy-load the inactive theme's fonts.
- Build as **design tokens / CSS variables** swapped at the `:root[data-theme]` level so one
  component set renders in either identity; dark tokens are the default.

---

## LOGO — CHOSEN 2026-09-27 (from "Cleave Logo v2")

**Mark: 6c — the "blade bow."** A recurve bow + nocked arrow, ink-only (monochrome), with
bladed/barbed limbs, an ornate diamond grip, a sighting ring, and barbed fletching.
Concept: the bow's curve doubles as the **C** of Cleave, and a bow = precision / the single
shot — which ties to the headline feature (the one minimum cut).

- **Asset:** `frontend/assets/cleave-mark.svg` — extracted from the mockup, cleaned, and
  made theme-aware (`fill="currentColor"`), 64×64 viewBox, ~1.4 KB. Verified in both themes.
- **Light (Field manual):** green ink `#2F5D46` on paper, wordmark in Newsreader serif.
- **Dark (Signal):** white `#F5F5F2` on black, wordmark in Geist. **Accent option:** tint
  the arrowhead signal-orange `#FF6A1A` (6d-style) so the dark mark carries the brand colour.
- **⚠ Small sizes:** the barbs/grip detail collapses below ~24px. Draw a **simplified 16px
  glyph** (bare recurve bow + arrow, no barbs) for favicon/small UI. Polish task, not blocking.
- Not final — chosen "for now"; revisit if it grates once it's living in the real UI.
