# OmniSec → Beyond XBOW: Deep Autonomous VAPT Roadmap

Goal: turn OmniSec into an AI-driven offensive security platform that out-performs XBOW on (a) breadth of OWASP/CWE coverage, (b) depth of multi-step exploitation, and (c) discovery of true zero-days — while staying lawful and reproducible.

## Where we are vs XBOW

XBOW's edge: parallel autonomous agents, per-target sandboxed VMs, validated PoCs, HackerOne-grade reports, learns from prior runs, no human-in-loop required.

What we already have:
- 25-chain VAPT orchestrator (Sprints 1–6), recon pipeline, OAST listener, payload mutation, scope validator, RLS-hardened backend.
- AI learning tables (`vapt_test_actions`, `vapt_feedback`, `vapt_suggestions`), explainability UI, scan history & PDF reports.

What's blocking us from beating XBOW today:
1. Scans stall mid-pipeline (chain trigger fragility, 150s edge limits).
2. AI "learning" writes rows but doesn't *retrieve* + *condition* future payloads on them.
3. Payloads are mostly static / template-mutated, not target-aware.
4. No real exploit sandbox — findings are signature-grade, not PoC-grade.
5. No agentic planner that reasons over recon → picks chains → re-plans on failure.
6. No cross-scan knowledge graph (assets, tech, vulns, exploit success).

## Strategy: 6 Pillars

### Pillar 1 — Reliable Execution Backbone
- Replace trigger-based pass chaining with a **durable job queue** (`scan_jobs` table + `scan-worker` edge function polled by pg_cron every 10s). Each job = one detector, idempotent, retried, owned by `scan_id`.
- Per-pass watchdog: if `updated_at` stale > 120s → mark failed, requeue once, then continue (no more 26% stalls).
- Realtime: workers publish to `scan_id` channel; UI shows live per-detector status.

### Pillar 2 — Agentic Planner (the "brain" XBOW has)
- New `vapt-planner` edge function using Gemini 2.5 Pro + tool calling.
- Tools exposed to the LLM: `runRecon`, `fetchTech`, `runDetector(name, params)`, `mutatePayload`, `verifyFinding`, `queryKnowledge`, `submitFinding`.
- Loop: observe target state → pick next best action → execute via worker → ingest result → re-plan. `stopWhen: stepCountIs(80)` or budget exhausted.
- Planner persists every decision + rationale to `vapt_test_actions` (already exists) so ExplainableAI shows reasoning chains.

### Pillar 3 — Target-Aware AI Payloads (real, not template)
- Recon enriches a **target context bundle**: tech stack, framework versions, WAF fingerprint, observed param names, response shapes, auth model, error signatures.
- Before each detector fires, `payload-generator` calls Gemini with `{context, vulnClass, priorFailures}` → returns ranked payload list.
- `payload-mutation` adds 5-tier evasion (case, encoding, comment-splitting, unicode, polyglot) keyed off the *specific* WAF detected.
- Failed payloads + WAF responses feed back into `vapt_feedback` so the next scan starts where the last one left off.

### Pillar 4 — Real Exploit Validation (PoC-grade, XBOW parity)
- Replace signature-only detectors with **dual confirmation**:
  1. Primary trigger (e.g., SQLi time delay).
  2. Independent secondary probe (boolean-based, OAST callback, or differential response).
- Findings only graduate to `verified` when both pass. Stored in `finding_exploit_proofs` with curl + Python PoC.
- Add a `vapt-sandbox` function that re-runs the exploit in isolation and records HTTP transcript → user gets a reproducible PoC.

### Pillar 5 — Cross-Scan Knowledge Graph & Zero-Day Hunting
- New tables: `kg_assets`, `kg_tech`, `kg_vuln_patterns`, `kg_exploit_outcomes` (graph-style, FKs on host/tech/CWE).
- Nightly job: `threat-intel-learn` pulls NVD, GitHub advisories, HackerOne disclosed reports → embeds them (Gemini embeddings) → stores in `kg_vuln_patterns`.
- Zero-day heuristic: when a detector sees a response pattern that (a) doesn't match any known CVE signature but (b) shows anomalous behavior (error leak, auth bypass, state change) → flag as **`candidate_zero_day`**, auto-spawn deeper variant fuzzing, alert user.
- Cross-target learning: if exploit X worked on tech Y on scan A, planner biases toward X whenever it sees Y again.

### Pillar 6 — Coverage Completion (A01–A10 + beyond)
- Audit every OWASP category against current detectors (matrix already in `OWASPCoverageMatrix.tsx`). Fill gaps:
  - A02 Crypto: TLS config, JWT alg confusion, weak randomness probes.
  - A04 Insecure Design: business-logic fuzzer (sequence/state mutation).
  - A06 Vulnerable Components: SBOM extraction + CVE join from KG.
  - A08 Integrity: CI/CD exposure, unsigned update endpoints.
  - A09 Logging: detect verbose error leaks (already partial).
  - A10 SSRF: extend with cloud-metadata, DNS rebinding, gopher/file scheme.
- Add **CWE Top 25 + API Top 10** as first-class detector tags so reports map both frameworks.

## Phased Delivery

```text
Phase 1 (Foundation)        Phase 2 (Brain)         Phase 3 (Depth)
─────────────────────       ─────────────────       ──────────────────
Durable job queue           Agentic planner LLM     Dual-confirm exploits
End-to-end scan reliability Target-aware payloads   Sandbox PoC runner
Live per-detector UI        Planner explainability  Coverage gap fill
                                                    Zero-day heuristic
                            Phase 4 (Knowledge)
                            ──────────────────────
                            KG + embeddings
                            Cross-scan learning
                            NVD/H1 ingestion
```

## Technical Section

New backend pieces:
- Tables: `scan_jobs(id, scan_id, detector, status, attempts, payload jsonb, result jsonb, updated_at)`, `kg_assets`, `kg_tech`, `kg_vuln_patterns(embedding vector(768))`, `kg_exploit_outcomes`.
- Extensions: `pgvector` for embeddings, `pg_cron` for queue polling.
- Edge fns: `vapt-planner` (Gemini 2.5 Pro + tools), `scan-worker` (queue consumer, 1 detector/invocation to dodge 150s), `vapt-sandbox` (PoC replay), `kg-ingest` (NVD/H1 → embeddings).
- Reuse: `payload-generator`, `payload-mutation`, `oast-listener`, `vapt-chains` detectors (call them from worker instead of trigger-chain).

Frontend:
- New `PlannerThoughts` panel under Autonomous Attack — live stream of planner decisions.
- New `KnowledgeGraph` viz tab — assets ↔ tech ↔ vulns.
- Per-finding "Replay PoC" button → calls `vapt-sandbox`.

Migration order: queue table + worker (unblocks current stalls) → planner → KG → sandbox.

## Out of Scope (this plan)
- Custom kernel sandboxing (Firecracker) — defer; sandbox runs in edge runtime first.
- Browser-based DOM exploitation runner (Playwright) — phase 5.
- Mobile/iOS/Android scanners.

## Open Questions
1. Scope of zero-day claims: flag internally only, or attempt automated CVE-style write-ups?
2. Budget per scan (LLM tokens / OAST callbacks / time) — what cap?
3. Should the planner be allowed to chain destructive actions (state-changing PoCs) in Field Mode, or always Lab-only?
4. Priority: ship Phase 1 reliability fix first this week, or kick off planner + reliability in parallel?
