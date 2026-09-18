# Project Log

> Workflow: at the end of each work session, Joaquin will ask Claude to update
> this file (and README status) so a new conversation can pick up accurately.
> Always read this file first before assuming nothing's been done.

## 2026-09-16 — Phase 1 complete: AWS account lockdown

Done:
- AWS account created. Landed on the current "Free plan": ~$100 credit at
  signup, up to $100 more via usage, up to $200 total, valid 6 months or
  until exhausted, then a 90-day window to upgrade to Paid before deletion.
  (Replaced the old "12 months free" model in 2025.)
- Root user secured with MFA (authenticator app).
- CloudWatch billing alarm live: triggers over $10 estimated charges, region
  us-east-1, SNS email subscription confirmed.
- Dedicated IAM user `cloudgoat-deployer` created — no console access,
  access-key/CLI only. AdministratorAccess attached directly (deliberate
  tradeoff: CloudGoat publishes no least-privilege policy and its footprint
  varies by scenario; this is a quarantined lab account, not a real client
  account — would not fly there). Access key saved by Joaquin in a password
  manager — not in this project, not in chat, not in the eventual GitHub repo.
- `ClaudeCowork` folder on laptopblau connected as the working directory for
  this project.

- Confirmed laptopblau (Lenovo) is booted into Ubuntu and linked to this
  Claude session — the "link Ubuntu device" item is closed.

Not started yet:
- Installing core tooling: git, Python 3.9+, AWS CLI v2, Terraform ≥1.5.0;
  running `aws configure` with the IAM user's access key.
- Installing and verifying CloudGoat, Prowler, ScoutSuite.
- Creating the GitHub repo and folder structure (`iac/`, `findings/`,
  `detection/`, README skeleton).
- Deploying a CloudGoat scenario, running the audits, starting the
  teach-then-test judgment loop on findings.
