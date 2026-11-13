# AWS Cloud Security Assessment Report

**Environment:** Isolated AWS lab account (CloudGoat `iam_privesc_by_rollback` scenario)
**Assessor:** Joaquin Vilalta
**Date:** November 2026
**Classification:** Portfolio / demonstration engagement

---

## Executive Summary

This assessment evaluated the security posture of an intentionally vulnerable AWS
environment and identified a **critical privilege-escalation path** that allows a
low-privileged user to obtain full administrative control of the account.

The core issue is an IAM policy that retains an older, admin-granting version in
its version history while handing the attached user permission to change which
version is active. Any holder of that user's credentials can restore the
admin-granting version in a single API call — no new policy, no password, no
obvious "grant" action — and then optionally revert the change to erase the
evidence from the policy's current state.

Notably, two automated configuration scanners (Prowler and ScoutSuite) did **not**
rate this issue as high-severity, because both inspect only the *currently active*
configuration and cannot see the dormant admin version waiting in the policy's
history. This gap between automated severity and real-world risk is a central
theme of the engagement: tooling is a starting point, not a substitute for
analyst judgment.

To close that gap, a custom detection capability was developed that reads AWS
CloudTrail activity logs and flags the escalation pattern directly — catching the
attack even after an attacker reverts the configuration to look clean.

**Findings at a glance:**

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| 1 | IAM policy version rollback privilege escalation | **Critical** | Open — remediation recommended |
| 2 | CloudTrail activity logging not configured | **Critical** | Remediated during engagement |
| 3 | Weak account password policy | Low | Open — proactive fix recommended |

---

## Scope & Methodology

**In scope:** a single, isolated AWS account provisioned solely for this
assessment, containing the resources created by the CloudGoat
`iam_privesc_by_rollback` scenario (one IAM user and one customer-managed IAM
policy with multiple stored versions).

**Out of scope:** all other AWS services and the administrative identity used to
provision the lab (see note below). The broader population of lower-priority
configuration findings surfaced by automated scanning was reviewed but not
individually analyzed. The raw scanner output was reviewed but is **not**
published in this repository — it contains unsanitized account identifiers and
resource details — so the curated findings below are the published record.

**Methodology:** the assessment combined three approaches —

- **Manual review and exploitation.** The privilege-escalation path was traced
  and executed by hand to confirm it was genuinely exploitable, rather than
  inferred from tooling output alone.
- **Automated configuration scanning.** Prowler and ScoutSuite were run against
  the account to establish a broad baseline of misconfigurations and to compare
  automated severity ratings against hands-on findings.
- **Custom detection engineering.** A Python tool was built to parse CloudTrail
  logs for the specific activity signature of the escalation, addressing a
  blind spot that point-in-time configuration scanning cannot cover.

**Note on the deployment identity:** an administrator-level IAM user was used to
build and tear down the lab environment. This is standard practice for
provisioning a test environment — analogous to an assessor's own tooling account
— and is explicitly excluded from the findings rather than reported as an
over-privileged user.

**Note on sanitization:** the AWS account ID and source IP addresses in the
evidence below have been redacted (`<ACCOUNT_ID>`, `<SOURCE_IP>`), as this report
is published in a public repository.

---

## Findings

### Finding 1 — IAM Policy Version Rollback Privilege Escalation

**Severity: Critical** (Impact: High · Likelihood: High)

**Affected resource:** IAM policy `cg-raynor-policy`, attached to IAM user
`raynor`.

**Description**

An IAM managed policy can store up to five versions, but only one is "default"
(active) at a time. Older versions are not deleted when a new one is set active —
they remain in the policy's history and can be reactivated at any time.

The affected policy's active version (v1) grants only limited, read-oriented
permissions. However, it also grants `iam:SetDefaultPolicyVersion` — the ability
to choose which stored version is active — and the policy's history contains a
version (v3) that grants full administrative access (`Allow` / `Action: *` /
`Resource: *`).

The combination is the vulnerability. A user starting with only the limited v1
permissions can enumerate the policy's versions, identify the admin-granting v3,
and set it as the active version — escalating from near-zero privilege to full
account administrator in a single API call, without creating any new policy or
performing any obvious "grant" action.

**Evidence**

The escalation was executed by hand to confirm it is genuinely exploitable:

- As `raynor`, listed the policy's versions and read each one; v3 was confirmed to
  grant `Action: *` on `Resource: *`.
- Set v3 as the default version via `aws iam set-default-policy-version`.
- Confirmed elevated access: account-wide `iam:ListUsers` succeeded as `raynor`
  after the flip.
- Reverted the default to v1 and re-verified with a cross-service action
  (`aws s3 ls`), which correctly returned `AccessDenied` — confirming the
  escalation, and the revert, both took effect.

**Why automated scanners under-rated this**

Prowler and ScoutSuite evaluate the policy's *current* active version. At scan
time the active version was the limited v1, so neither tool surfaced this as a
high-severity privilege-escalation path. The dangerous v3 was dormant in the
policy's history — invisible to point-in-time configuration analysis, but one API
call away from being active.

**Remediation**

The attack requires two conditions to hold simultaneously, and removing *either*
one breaks it. Both are recommended (defense in depth):

1. **Remove `iam:SetDefaultPolicyVersion` from the user's permissions.** The
   `raynor` user has no legitimate need to change policy versions; removing this
   permission eliminates the escalation mechanism.
2. **Delete unused policy versions**, especially the admin-granting v3. If no
   over-privileged version exists in the history, there is nothing dangerous to
   roll back to.

**Secondary observation:** even the "limited" v1 uses broad wildcards
(`iam:Get*`, `iam:List*`), which grant more read access than is likely intended
(for example, account-wide `iam:ListUsers`). Scoping these to only the actions
the user actually requires would further reduce the account's attack surface, in
line with least-privilege principles.

---

### Finding 2 — CloudTrail Activity Logging Not Configured

**Severity: Critical** (Impact: High · Likelihood: High) · **Status: Remediated during engagement**

**Description**

At the start of the assessment the account had no configured CloudTrail trail.
AWS retains a rolling 90-day "Event History" of management events by default, but
this is short-lived, is not delivered to durable storage, and is not suitable as
a monitored, long-term audit source. Without a trail, there is no durable record
of security-relevant activity in the account.

This is a *detective*-control gap rather than an exploitable vulnerability — it
does not by itself let an attacker do anything. Its severity comes from context:
this same account contains a demonstrated, trivially-exploitable critical
escalation (Finding 1). An attacker could perform that escalation, act with
admin rights, revert the policy, and — without durable logging — leave almost no
lasting evidence. The absence of logging therefore directly undermines the
ability to detect or investigate the account's most serious risk.

**Remediation (applied)**

A durable logging pipeline was configured during the engagement:

- Created a dedicated S3 bucket to receive CloudTrail logs.
- Applied a bucket policy granting the CloudTrail service write access to that
  bucket (and nothing more).
- Created a multi-region trail and confirmed it was actively logging.

Multi-region coverage was chosen deliberately: IAM is a global service whose
events are recorded in `us-east-1`, so single-region logging could miss
identity-related activity depending on configuration.

This remediation also enabled the detection capability described below.

---

### Finding 3 — Weak Account Password Policy

**Severity: Low** (Impact: Low · Likelihood: Low)

**Description**

Automated scanning flagged the account's IAM password policy as weak: minimum
password length too short, no password expiration, and password reuse permitted.

In isolation these settings are a legitimate hardening gap. However, the actual
current exposure is minimal: a review of the account's credential report
confirmed that **no IAM user authenticates with a console password** — all
users are access-key (programmatic) only. The only identity with a password is
the account root user, which is not governed by the IAM account password policy
and is already protected with multi-factor authentication.

The finding is therefore rated Low: the misconfiguration is real, but there is
currently no identity it meaningfully affects.

**Remediation**

Set a strong account password policy proactively (reasonable minimum length,
expiration, and reuse prevention) so that the control is already in place before
any console-login user is ever created. This is low-urgency hardening rather than
an active exposure.

---

## Detection Engineering

Finding 1 exposed a structural limitation of configuration scanning: it cannot
detect an attack whose evidence exists only in the *sequence of actions taken*,
not in the current state of the account. After an attacker reverts the policy,
the configuration looks clean again — but the activity log still records what
happened.

To cover this gap, a custom detection tool (`detection/detect_policy_rollback.py`,
Python / boto3) was built. It reads CloudTrail history for
`SetDefaultPolicyVersion` calls and applies the following logic:

- **HIGH — escalate-then-revert:** the same policy's default version is changed
  two or more times within a configurable window (default 24 hours). Flipping a
  policy's active version and then flipping it again in a short span is the
  classic "cover your tracks" round-trip and has almost no legitimate explanation.
- **HIGH — flip to admin:** a single change that activates a full-admin version
  (`Allow` / `Action: *` / `Resource: *`), even with no revert, because
  escalating to full administrator is serious regardless of whether the attacker
  covers their tracks.
- **NOTEWORTHY:** any other single `SetDefaultPolicyVersion` call. The API is rare
  in normal operations, so even one occurrence warrants a human look.

For each change, the tool fetches the activated version's document to determine
whether it grants administrative access, so the output distinguishes a flip to a
harmless version from a flip to an admin version.

**Validation.** Run against the account's real CloudTrail history, the tool
correctly identified the escalation performed during this assessment as a single
**HIGH / escalate-then-revert** finding — reporting both version changes in
sequence, flagging the admin version, and capturing the acting identity and
source IP. It detected the genuine attack, not a synthetic test case.

**Known limitations (by design):**

- **Partial-admin versions are not auto-escalated.** The admin check matches only
  the full `Action: *` / `Resource: *` grant. A "near-admin" version (for example,
  `iam:*`) would still be caught if it is part of a round-trip, but a one-way flip
  to such a version is not automatically rated HIGH. Deciding which partial
  permission sets count as "dangerous" is environment-specific judgment that was
  deliberately kept out of scope for this version, to avoid false positives.
- **90-day history window.** The tool reads CloudTrail Event History, which covers
  roughly the last 90 days. For longer retention, it would read from the durable
  S3 trail configured in Finding 2's remediation.
- **Detection complements, not replaces, prevention.** This tool detects the
  attack; it does not prevent it. The remediations in Finding 1 remain the primary
  fix. Detection exists as a defense-in-depth layer for cases where prevention was
  missed, cannot be applied, or needs to be verified.

---

## Out of Scope / Future Work

- **Broader scanner findings.** Prowler and ScoutSuite surfaced a larger set of
  lower-priority configuration findings, heavily duplicated across compliance
  frameworks. These were reviewed but not individually analyzed, and the raw
  output is not published here for the same sanitization reason noted in the
  methodology.
- **Partial-admin detection.** The detection tool could be extended with a
  configurable model of "dangerous" permission patterns beyond full admin.
- **Continuous monitoring.** The tool currently runs on demand. In a production
  setting it would read from the durable S3 trail and feed an alerting pipeline
  (for example, EventBridge → SNS) for near-real-time notification rather than
  retrospective review.
