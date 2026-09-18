# AWS Cloud Security Assessment & Detection Pipeline

Status: **Phase 1 (AWS account lockdown) complete — moving into tooling setup**
Target completion: early-to-mid October 2026

See `NOTES.md` for the running session log — always check it first in a new
conversation before assuming nothing's been done.

## What this project is

Deploy an intentionally vulnerable AWS environment (CloudGoat), audit it with
Prowler and ScoutSuite, score and write up the findings like a consulting
engagement, then build a Python script that parses CloudTrail logs to flag
anomalous IAM activity.

## Scope

1. **Environment** — Deploy CloudGoat on AWS Free Tier. Billing alarm set up
   *before* touching resources. ✅ done
2. **Audit** — Run Prowler and ScoutSuite against the environment. Review raw
   findings.
3. **Detection layer** — Python script parsing CloudTrail logs to flag
   anomalous IAM activity (privilege escalation, unexpected role assumption,
   etc.)
4. **Deliverable** — GitHub repo with setup scripts/IaC, a client-style
   findings report (severity + remediation), README.

## How AI assistance is used here (disclosed, on purpose)

Claude accelerates the build (scaffolding, boilerplate, code). Joaquin drives
all the security judgment — which findings matter, severity scoring,
remediation calls, the "what would I tell a client" decisions — via a
teach-then-test loop: Claude teaches a framework once, then hands over raw
findings for Joaquin to score *before* Claude weighs in.

Bar for "this is honestly mine": able to reason through a novel, made-up
misconfiguration scenario out loud in an interview, unprompted, using the
framework — not just recite this project's specific findings.

## Repo layout (fills in as we go)

```
aws-cloud-security-project/
├── README.md
├── NOTES.md              # running log: what's done, decisions, blockers
├── terraform/             # CloudGoat / IaC
├── scripts/                # setup + detection scripts
└── report/                 # findings report drafts
```
