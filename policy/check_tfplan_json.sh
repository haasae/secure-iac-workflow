#!/usr/bin/env bash
set -euo pipefail

PLAN_JSON_PATH="${1:-infra/tfplan.json}"

if [[ ! -f "$PLAN_JSON_PATH" ]]; then
  echo "Policy check failed: plan JSON not found at $PLAN_JSON_PATH"
  exit 1
fi

PYTHON_BIN=""
if command -v python3 >/dev/null 2>&1 && python3 -c "import sys" >/dev/null 2>&1; then
  PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1 && python -c "import sys" >/dev/null 2>&1; then
  PYTHON_BIN="python"
else
  echo "Policy check failed: python3/python is required to parse tfplan.json"
  exit 1
fi

"$PYTHON_BIN" - "$PLAN_JSON_PATH" <<'PY'
import json
import sys

plan_path = sys.argv[1]

with open(plan_path, "rb") as f:
    raw = f.read()

decoded = None
for enc in ("utf-8-sig", "utf-16", "utf-16-le", "utf-16-be"):
    try:
        decoded = raw.decode(enc)
        break
    except UnicodeDecodeError:
        continue

if decoded is None:
    print("Policy check failed: tfplan.json is not valid UTF-8/UTF-16 text")
    sys.exit(1)

plan = json.loads(decoded)

changes = plan.get("resource_changes", [])
pab_changes = [
    rc for rc in changes
    if rc.get("type") == "aws_s3_bucket_public_access_block"
]
versioning_changes = [
    rc for rc in changes
    if rc.get("type") == "aws_s3_bucket_versioning"
]
encryption_changes = [
    rc for rc in changes
    if rc.get("type") == "aws_s3_bucket_server_side_encryption_configuration"
]

if not pab_changes:
    print("Policy check failed: aws_s3_bucket_public_access_block is missing from tfplan.json")
    sys.exit(1)

required_fields = [
    "block_public_acls",
    "ignore_public_acls",
    "block_public_policy",
    "restrict_public_buckets",
]

for rc in pab_changes:
    actions = rc.get("change", {}).get("actions", [])
    if "delete" in actions and len(actions) == 1:
        continue

    after = rc.get("change", {}).get("after") or {}
    missing_or_false = [field for field in required_fields if after.get(field) is not True]
    if missing_or_false:
        print(
            "Policy check failed: public access block settings must be true in plan: "
            + ", ".join(missing_or_false)
        )
        sys.exit(1)

print("Policy check passed: tfplan.json includes S3 public access block with all protections enabled.")

if not versioning_changes:
    print("Policy check failed: aws_s3_bucket_versioning is missing from tfplan.json")
    sys.exit(1)

for rc in versioning_changes:
    actions = rc.get("change", {}).get("actions", [])
    if "delete" in actions and len(actions) == 1:
        continue

    after = rc.get("change", {}).get("after") or {}
    versioning = after.get("versioning_configuration") or []

    if not versioning:
        print("Policy check failed: aws_s3_bucket_versioning has no versioning_configuration in plan")
        sys.exit(1)

    status = versioning[0].get("status")
    if status != "Enabled":
        print(
            "Policy check failed: S3 versioning must be Enabled in plan "
            f"(found: {status!r})"
        )
        sys.exit(1)

print("Policy check passed: tfplan.json includes S3 versioning enabled.")

if not encryption_changes:
    print("Policy check failed: aws_s3_bucket_server_side_encryption_configuration is missing from tfplan.json")
    sys.exit(1)

for rc in encryption_changes:
    actions = rc.get("change", {}).get("actions", [])
    if "delete" in actions and len(actions) == 1:
        continue

    after = rc.get("change", {}).get("after") or {}
    rules = after.get("rule") or []

    if not rules:
        print("Policy check failed: S3 encryption configuration has no rule in plan")
        sys.exit(1)

    first_rule = rules[0] if isinstance(rules, list) else rules
    default_cfg = first_rule.get("apply_server_side_encryption_by_default") or []
    if isinstance(default_cfg, list):
        default_cfg = default_cfg[0] if default_cfg else {}

    sse_algorithm = default_cfg.get("sse_algorithm")
    if sse_algorithm not in ("AES256", "aws:kms"):
        print(
            "Policy check failed: S3 default encryption must use AES256 or aws:kms in plan "
            f"(found: {sse_algorithm!r})"
        )
        sys.exit(1)

print("Policy check passed: tfplan.json includes S3 default encryption.")
PY
