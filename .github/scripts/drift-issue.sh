#!/usr/bin/env bash
# Turns the policy check into one GitHub issue: opened on drift, updated only when the drift
# changes (fingerprint), closed when every policy is compliant again.
set -euo pipefail

label="policy-drift"
report="${REPORT:-drift.md}"
run_url="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"

gh label create "$label" --color D93F0B \
  --description "Network policy drift found by the scheduled check" 2>/dev/null || true

number=$(gh issue list --label "$label" --state open --json number --jq '.[0].number // empty')
fingerprint=$(grep -o 'fingerprint: [0-9a-f]*' "$report" | cut -d' ' -f2)

if [ "$DRIFT" = "true" ]; then
  if [ -z "$number" ]; then
    gh issue create --label "$label" --body-file "$report" \
      --title "Policy drift on ${INVENTORY}"
  else
    previous=$(gh issue view "$number" --json body --jq .body \
      | grep -o 'fingerprint: [0-9a-f]*' | cut -d' ' -f2 || true)
    if [ "$previous" = "$fingerprint" ]; then
      echo "Same drift as issue #${number}: nothing to update."
    else
      gh issue edit "$number" --body-file "$report"
      gh issue comment "$number" --body "The drift changed ([run](${run_url})): description updated."
    fi
  fi
elif [ -n "$number" ]; then
  gh issue comment "$number" --body "Every policy is compliant again ([run](${run_url})). Closing."
  gh issue close "$number"
else
  echo "Compliant, no open drift issue."
fi
