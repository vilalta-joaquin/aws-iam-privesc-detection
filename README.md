# AWS Cloud Security Assessment & Detection Pipeline

A hands-on cloud security assessment of an intentionally vulnerable AWS
environment: manual exploitation, automated scanning, severity analysis, and a
custom CloudTrail-based detection tool for the attack the scanners missed.

> **Note:** This is a portfolio / learning engagement performed against an
> isolated lab account built with
> [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat)
> (the `iam_privesc_by_rollback` scenario). It is not a real client engagement.
> Account identifiers and source IPs are redacted throughout.

## Headline

A low-privileged IAM user was able to escalate to **full account administrator
in a single API call**, by rolling an IAM policy back to a dormant,
admin-granting version left in its version history. Two automated configuration
scanners (Prowler and ScoutSuite) did **not** flag this as high-severity,
because they inspect only the *currently active* configuration and cannot see a
dangerous version sitting dormant in a policy's history. A custom detection tool
closes that gap by reading CloudTrail activity logs, catching the attack even
after the configuration is reverted to look clean.

Full write-up: **[`findings/assessment-report.md`](findings/assessment-report.md)**.

## The findings

| # | Finding | Severity |
|---|---------|----------|
| 1 | IAM policy version rollback privilege escalation | Critical |
| 2 | CloudTrail activity logging not configured (remediated) | Critical |
| 3 | Weak account password policy | Low |

## What's in this repo

- **`findings/assessment-report.md`** — the client-style assessment report:
  executive summary, scope & methodology, the three scored findings with
  remediation, and the detection-engineering write-up. *Start here.*
- **`detection/detect_policy_rollback.py`** — Python / boto3 tool that parses
  CloudTrail history for the policy-rollback attack signature.
- **`iac/cloudtrail-bucket-policy.json`** — the S3 bucket policy used to stand
  up durable CloudTrail logging (one of the remediations). The account ID is a
  `<ACCOUNT_ID>` placeholder — substitute your own to reuse it.
- **`requirements.txt`** — Python dependencies for the detection tool.

Raw Prowler/ScoutSuite scan output is intentionally **not** published, as it
contains unsanitized account identifiers and resource detail; the report is the
curated record of what the scans found.

## Running the detection tool

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python3 detection/detect_policy_rollback.py --profile <your-aws-profile>
```

It reads CloudTrail for `SetDefaultPolicyVersion` activity and reports:

- **HIGH** — a policy's default version changed two or more times within a
  window (the escalate-then-revert round-trip), or a single change to a
  full-admin version.
- **NOTEWORTHY** — any other single version change (rare enough to be worth a
  look).

Run with `--help` for options (AWS profile, region, lookback window, revert
window, and whether to inspect each version's granted permissions).

## A note on AI assistance

Code scaffolding and implementation were accelerated with AI assistance. The
security judgment — which findings matter, how they are scored, the remediation
recommendations, and the detection logic itself — is my own, developed by
reasoning through each decision rather than accepting generated output at face
value.

## Tools used

AWS CLI, Terraform, CloudGoat, Prowler, ScoutSuite, Python (boto3), AWS
CloudTrail, IAM.
