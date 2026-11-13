#!/usr/bin/env python3
"""
detect_policy_rollback.py

Detects the IAM "policy version rollback" privilege-escalation pattern by
reading AWS CloudTrail management-event history.

Background
----------
An IAM managed policy keeps up to five versions. Only one is the "default"
(active) version at a time, but the others are NOT deleted — they stay in the
policy's history. Any principal holding the `iam:SetDefaultPolicyVersion`
permission can switch the active version to any stored version. If an older
version grants more access than the current one, flipping back to it is a
privilege escalation that writes no new policy and performs no obvious "grant"
action.

A point-in-time configuration scanner (Prowler, ScoutSuite, AWS Config) cannot
catch this reliably: it only sees whichever version is active at scan time. The
evidence lives in the *activity log* — the `SetDefaultPolicyVersion` API calls
themselves — which is what this script inspects.

What it flags
-------------
NOTEWORTHY: a single `SetDefaultPolicyVersion` call to a non-admin version.
This API is rare in normal operations, so even one call is worth a human look.

HIGH, for either of two reasons:
  * Escalate-then-revert — the same policy's default is changed two or more
    times within the window. Flipping a policy's active version and then
    flipping it again in a short span is the classic "cover your tracks"
    round-trip: use an elevated version, then restore the original so the
    policy looks untouched. (Two+ flips on one policy inside 24h has almost no
    legitimate explanation.) Note: we deliberately do NOT require the second
    flip to return to a version seen earlier in the logs — an attacker
    reverting to the policy's ORIGINAL default (set at creation, never by a
    logged flip) would otherwise slip through.
  * Flip to admin — any single flip that activates an admin-granting version
    (Allow / Action "*" / Resource "*"), even with no revert. Escalating to
    full admin is serious whether or not the attacker bothers to cover tracks.

Known limitation (documented, not coded): the admin check matches only the full
"*" / "*" grant. A "near-admin" version (e.g. `iam:*`) is still caught as a
round-trip if it is flipped more than once, but a one-way flip to such a version
is not auto-escalated to HIGH, because deciding which partial permission sets
count as "dangerous" is environment-specific judgment, deliberately out of scope
for v1.

Why us-east-1
-------------
IAM is a global service; its CloudTrail events are always recorded in the
us-east-1 region regardless of where the caller was. So that is the region this
script queries by default. Point it elsewhere only if you know your IAM events
land elsewhere (they almost never do).

Usage
-----
    python3 detect_policy_rollback.py --profile default
    python3 detect_policy_rollback.py --days 30 --revert-window-hours 12
    python3 detect_policy_rollback.py --no-inspect-permissions
"""

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone

try:
    import boto3
    from botocore.exceptions import ClientError, BotoCoreError
except ImportError:
    sys.exit("boto3 is required. Install it with:  pip install boto3")


EVENT_NAME = "SetDefaultPolicyVersion"


# ---------------------------------------------------------------------------
# Step 1 — pull the raw events from CloudTrail
# ---------------------------------------------------------------------------
def fetch_events(ct_client, days):
    """
    Pull every SetDefaultPolicyVersion event CloudTrail has recorded in the
    lookback window. CloudTrail's free Event History keeps ~90 days of
    management events, so `days` cannot usefully exceed 90.

    Returns a list of dicts, one per flip, sorted oldest-first.
    """
    start = datetime.now(timezone.utc) - timedelta(days=days)
    events = []

    # lookup_events returns results in pages; NextToken walks through them.
    paginator = ct_client.get_paginator("lookup_events")
    pages = paginator.paginate(
        LookupAttributes=[
            {"AttributeKey": "EventName", "AttributeValue": EVENT_NAME}
        ],
        StartTime=start,
        EndTime=datetime.now(timezone.utc),
    )

    for page in pages:
        for raw in page.get("Events", []):
            parsed = parse_event(raw)
            if parsed:
                events.append(parsed)

    # Oldest-first makes the escalate-then-revert sequence read in order.
    events.sort(key=lambda e: e["time"])
    return events


def parse_event(raw):
    """
    Pull the fields we care about out of one CloudTrail event.

    The useful detail is inside `CloudTrailEvent`, which CloudTrail hands back
    as a JSON *string*, so it has to be parsed a second time.
    """
    try:
        detail = json.loads(raw["CloudTrailEvent"])
    except (KeyError, json.JSONDecodeError):
        return None

    req = detail.get("requestParameters") or {}
    identity = detail.get("userIdentity") or {}

    return {
        "time": raw["EventTime"],                       # tz-aware datetime (UTC)
        "policy_arn": req.get("policyArn", "UNKNOWN"),
        "version_id": req.get("versionId", "UNKNOWN"),  # the version made default
        "actor": identity.get("arn", identity.get("userName", "UNKNOWN")),
        "source_ip": detail.get("sourceIPAddress", "UNKNOWN"),
        "event_id": raw.get("EventId", ""),
    }


# ---------------------------------------------------------------------------
# Step 2 — detect the escalate-then-revert round-trip
# ---------------------------------------------------------------------------
def detect_round_trips(events, window_hours):
    """
    Flag any policy whose default version is changed two or more times with a
    consecutive pair of changes falling within `window_hours` of each other.

    Rationale: changing a policy's active version even once is rare; changing
    it again within a short window is the escalate-then-revert round-trip. We
    deliberately do NOT require the second flip to return to a specific earlier
    version — an attacker reverting to the policy's ORIGINAL default (which was
    set at creation, not by a logged flip) would otherwise be missed.

    Returns: policy_arn -> list of its flips, for policies that qualify.
    """
    window = timedelta(hours=window_hours)
    by_policy = defaultdict(list)
    for e in events:
        by_policy[e["policy_arn"]].append(e)

    flagged = {}
    for policy_arn, flips in by_policy.items():
        if len(flips) < 2:
            continue
        # flips are time-sorted; any consecutive pair within the window qualifies
        for earlier, later in zip(flips, flips[1:]):
            if later["time"] - earlier["time"] <= window:
                flagged[policy_arn] = flips
                break

    return flagged


# ---------------------------------------------------------------------------
# Step 3 (optional) — inspect what each activated version actually grants
# ---------------------------------------------------------------------------
def version_is_admin(iam_client, policy_arn, version_id):
    """
    Fetch a specific policy version and decide whether it grants admin-level
    access: any Allow statement with Action "*" and Resource "*".

    Returns True / False, or None if the version could not be read (e.g. the
    policy or version no longer exists — common once a lab is torn down).
    """
    try:
        resp = iam_client.get_policy_version(
            PolicyArn=policy_arn, VersionId=version_id
        )
    except (ClientError, BotoCoreError):
        return None  # degrade gracefully instead of crashing

    document = resp["PolicyVersion"]["Document"]  # already a dict from boto3
    statements = document.get("Statement", [])
    if isinstance(statements, dict):      # a single statement isn't wrapped in a list
        statements = [statements]

    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        if "*" in actions and "*" in resources:
            return True
    return False


def enrich_admin_flags(iam_client, events):
    """Annotate each flip with whether the version it activated is admin-level.
    Cached per (policy, version) so we don't re-fetch the same version."""
    cache = {}
    for e in events:
        key = (e["policy_arn"], e["version_id"])
        if key not in cache:
            cache[key] = version_is_admin(iam_client, *key)
        e["is_admin"] = cache[key]


# ---------------------------------------------------------------------------
# Step 4 — report
# ---------------------------------------------------------------------------
def build_report(all_events, round_trips, inspected):
    """Assemble a structured result. Severity rules:
       HIGH  = policy shows the round-trip pattern, OR a single flip to an
               admin-granting version.
       NOTEWORTHY = any other single flip."""
    findings = []
    round_trip_policies = set(round_trips.keys())

    # HIGH (a) — one finding per policy that shows the round-trip pattern.
    for policy_arn, flips in round_trips.items():
        admin_hit = any(f.get("is_admin") for f in flips) if inspected else None
        findings.append({
            "severity": "HIGH",
            "pattern": "escalate-then-revert",
            "policy_arn": policy_arn,
            "flip_count": len(flips),
            "activated_admin_version": admin_hit,
            "sequence": [
                {
                    "time": f["time"].isoformat(),
                    "version_id": f["version_id"],
                    "is_admin": f.get("is_admin") if inspected else None,
                    "actor": f["actor"],
                    "source_ip": f["source_ip"],
                }
                for f in flips
            ],
        })

    # Flips on policies that did NOT show a round-trip.
    for e in all_events:
        if e["policy_arn"] in round_trip_policies:
            continue
        # HIGH (b) — a lone flip straight to an admin version, revert or not.
        if inspected and e.get("is_admin"):
            findings.append({
                "severity": "HIGH",
                "pattern": "flip-to-admin",
                "policy_arn": e["policy_arn"],
                "version_id": e["version_id"],
                "activated_admin_version": True,
                "time": e["time"].isoformat(),
                "actor": e["actor"],
                "source_ip": e["source_ip"],
            })
        else:
            # NOTEWORTHY — single flip to a non-admin (or uninspected) version.
            findings.append({
                "severity": "NOTEWORTHY",
                "pattern": "single-flip",
                "policy_arn": e["policy_arn"],
                "version_id": e["version_id"],
                "activated_admin_version": e.get("is_admin") if inspected else None,
                "time": e["time"].isoformat(),
                "actor": e["actor"],
                "source_ip": e["source_ip"],
            })

    return findings


def print_summary(findings, total_events, inspected):
    print("=" * 70)
    print("IAM Policy Version Rollback — CloudTrail Detection")
    print("=" * 70)
    print(f"SetDefaultPolicyVersion calls found: {total_events}")
    high = [f for f in findings if f["severity"] == "HIGH"]
    note = [f for f in findings if f["severity"] == "NOTEWORTHY"]
    print(f"HIGH:        {len(high)}")
    print(f"NOTEWORTHY:  {len(note)}")
    print("-" * 70)

    for f in high:
        if f["pattern"] == "escalate-then-revert":
            print(f"\n[HIGH] escalate-then-revert on {f['policy_arn']}")
            if inspected:
                print(f"       flipped to an admin-granting version: "
                      f"{f['activated_admin_version']}")
            for step in f["sequence"]:
                admin = ""
                if inspected and step["is_admin"] is not None:
                    admin = "  (ADMIN)" if step["is_admin"] else ""
                print(f"       {step['time']}  ->  {step['version_id']}{admin}"
                      f"   by {step['actor']} from {step['source_ip']}")
        else:  # flip-to-admin
            print(f"\n[HIGH] flip to admin version on {f['policy_arn']}")
            print(f"       {f['time']}  ->  {f['version_id']}  (ADMIN)"
                  f"   by {f['actor']} from {f['source_ip']}")

    for f in note:
        admin = ""
        if inspected and f["activated_admin_version"] is not None:
            admin = "  (ADMIN)" if f["activated_admin_version"] else ""
        print(f"\n[NOTEWORTHY] {f['time']}  {f['policy_arn']}  "
              f"-> {f['version_id']}{admin}")
        print(f"             by {f['actor']} from {f['source_ip']}")

    if not findings:
        print("\nNo SetDefaultPolicyVersion activity in the lookback window.")
    print()


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="Detect IAM policy-version rollback privilege escalation "
                    "from CloudTrail Event History."
    )
    ap.add_argument("--profile", default="default",
                    help="AWS CLI profile to use (default: default).")
    ap.add_argument("--region", default="us-east-1",
                    help="Region to query. IAM events land in us-east-1 "
                         "(default: us-east-1).")
    ap.add_argument("--days", type=int, default=90,
                    help="Lookback window in days (max ~90 for Event "
                         "History; default: 90).")
    ap.add_argument("--revert-window-hours", type=int, default=24,
                    help="Max hours between two flips on one policy for them to "
                         "count as an escalate-then-revert round-trip "
                         "(default: 24).")
    ap.add_argument("--no-inspect-permissions", action="store_true",
                    help="Skip fetching each version's document to check for "
                         "admin grants (fewer API calls, less context).")
    ap.add_argument("--json", metavar="PATH",
                    help="Also write the structured findings to this JSON file.")
    args = ap.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    ct_client = session.client("cloudtrail")

    events = fetch_events(ct_client, args.days)

    inspected = not args.no_inspect_permissions
    if inspected and events:
        enrich_admin_flags(session.client("iam"), events)

    round_trips = detect_round_trips(events, args.revert_window_hours)
    findings = build_report(events, round_trips, inspected)

    print_summary(findings, len(events), inspected)

    if args.json:
        with open(args.json, "w") as fh:
            json.dump(findings, fh, indent=2)
        print(f"Structured findings written to {args.json}")


if __name__ == "__main__":
    main()
