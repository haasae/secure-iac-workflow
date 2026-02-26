#!/usr/bin/env bash
set -euo pipefail

TARGET_DIR="infra"

if ! grep -R -q 'resource "aws_s3_bucket_public_access_block"' "$TARGET_DIR"/*.tf; then
  echo "Policy check failed: aws_s3_bucket_public_access_block resource is missing in $TARGET_DIR/."
  exit 1
fi

for required in \
  'block_public_acls *= *true' \
  'ignore_public_acls *= *true' \
  'block_public_policy *= *true' \
  'restrict_public_buckets *= *true'
do
  if ! grep -R -E -q "$required" "$TARGET_DIR"/*.tf; then
    echo "Policy check failed: expected setting not found: $required"
    exit 1
  fi
done

echo "Policy check passed: S3 public access block is present and enabled."