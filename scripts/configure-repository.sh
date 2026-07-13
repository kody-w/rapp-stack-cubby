#!/bin/sh
set -eu

REPOSITORY=
MAIN_BRANCH=main
REVIEWER_USER_ID=
REVIEWER_TEAM_ID=

while [ "$#" -gt 0 ]; do
  case "$1" in
    --repo) REPOSITORY=$2; shift 2 ;;
    --main-branch) MAIN_BRANCH=$2; shift 2 ;;
    --reviewer-user-id) REVIEWER_USER_ID=$2; shift 2 ;;
    --reviewer-team-id) REVIEWER_TEAM_ID=$2; shift 2 ;;
    *) echo "error: unsupported repository setting argument: $1" >&2; exit 2 ;;
  esac
done

case "$REPOSITORY" in
  */*) ;;
  *) echo "error: --repo must be OWNER/REPOSITORY" >&2; exit 2 ;;
esac
OWNER=${REPOSITORY%%/*}
REPOSITORY_NAME=${REPOSITORY#*/}
case "$OWNER" in
  ''|*[!A-Za-z0-9_.-]*) echo "error: repository owner is invalid" >&2; exit 2 ;;
esac
case "$REPOSITORY_NAME" in
  ''|*[!A-Za-z0-9_.-]*|*/*)
    echo "error: repository name is invalid" >&2
    exit 2
    ;;
esac
case "$MAIN_BRANCH" in
  ''|*[!A-Za-z0-9._/-]*) echo "error: main branch is invalid" >&2; exit 2 ;;
esac
if [ -z "$REVIEWER_USER_ID" ] && [ -z "$REVIEWER_TEAM_ID" ]; then
  echo "error: at least one explicit reviewer ID is required" >&2
  exit 2
fi
for REVIEWER_ID in "$REVIEWER_USER_ID" "$REVIEWER_TEAM_ID"
do
  case "$REVIEWER_ID" in
    '') ;;
    *[!0-9]*) echo "error: reviewer IDs must be numeric API IDs" >&2; exit 2 ;;
  esac
done

command -v gh >/dev/null 2>&1 || {
  echo "error: gh is required" >&2
  exit 2
}
PYTHON_COMMAND=${PYTHON:-python3}

api_input() {
  METHOD=$1
  ENDPOINT=$2
  PAYLOAD=$3
  printf '%s\n' "$PAYLOAD" |
    gh api --method "$METHOD" \
      -H "Accept: application/vnd.github+json" \
      "$ENDPOINT" --input - >/dev/null
}

gh api -H "Accept: application/vnd.github+json" \
  "repos/$REPOSITORY" >/dev/null

PAGES_PAYLOAD='{"build_type":"workflow"}'
if ! api_input PUT "repos/$REPOSITORY/pages" "$PAGES_PAYLOAD" 2>/dev/null; then
  api_input POST "repos/$REPOSITORY/pages" "$PAGES_PAYLOAD"
fi

PROTECTION_PAYLOAD='{
  "allow_deletions": false,
  "allow_force_pushes": false,
  "block_creations": false,
  "enforce_admins": true,
  "lock_branch": false,
  "required_conversation_resolution": true,
  "required_linear_history": true,
  "required_pull_request_reviews": {
    "dismiss_stale_reviews": true,
    "require_code_owner_reviews": true,
    "require_last_push_approval": true,
    "required_approving_review_count": 1
  },
  "required_status_checks": {
    "contexts": ["verify"],
    "strict": true
  },
  "restrictions": null
}'
api_input PUT \
  "repos/$REPOSITORY/branches/$MAIN_BRANCH/protection" \
  "$PROTECTION_PAYLOAD"

gh api --method PUT \
  -H "Accept: application/vnd.github+json" \
  "repos/$REPOSITORY/immutable_releases/enforcement" >/dev/null

TAG_RULESET_NAME='immutable-release-tags'
TAG_RULESET_PAYLOAD='{
  "bypass_actors": [],
  "conditions": {
    "ref_name": {
      "exclude": [],
      "include": ["refs/tags/*"]
    }
  },
  "enforcement": "active",
  "name": "immutable-release-tags",
  "rules": [
    {"type": "deletion"},
    {"type": "update"}
  ],
  "target": "tag"
}'
RULESET_IDS=$(
  gh api -H "Accept: application/vnd.github+json" \
    "repos/$REPOSITORY/rulesets" \
    --jq '.[] | select(.name == "immutable-release-tags") | .id'
)
case "$RULESET_IDS" in
  '') api_input POST "repos/$REPOSITORY/rulesets" "$TAG_RULESET_PAYLOAD" ;;
  *'
'*) echo "error: duplicate immutable tag rulesets exist" >&2; exit 2 ;;
  *) api_input PUT "repos/$REPOSITORY/rulesets/$RULESET_IDS" "$TAG_RULESET_PAYLOAD" ;;
esac

REVIEWERS=$(
  "$PYTHON_COMMAND" - "$REVIEWER_USER_ID" "$REVIEWER_TEAM_ID" <<'PY'
import json
import sys

values = []
if sys.argv[1]:
    values.append({"id": int(sys.argv[1]), "type": "User"})
if sys.argv[2]:
    values.append({"id": int(sys.argv[2]), "type": "Team"})
print(json.dumps(values, separators=(",", ":"), sort_keys=True))
PY
)
ENVIRONMENT_PAYLOAD=$(
  "$PYTHON_COMMAND" - "$REVIEWERS" <<'PY'
import json
import sys

print(json.dumps({
    "deployment_branch_policy": {
        "custom_branch_policies": True,
        "protected_branches": False,
    },
    "prevent_self_review": True,
    "reviewers": json.loads(sys.argv[1]),
    "wait_timer": 0,
}, separators=(",", ":"), sort_keys=True))
PY
)
for ENVIRONMENT in release promotion
do
  api_input PUT \
    "repos/$REPOSITORY/environments/$ENVIRONMENT" \
    "$ENVIRONMENT_PAYLOAD"
  POLICIES=$(
    gh api -H "Accept: application/vnd.github+json" \
      "repos/$REPOSITORY/environments/$ENVIRONMENT/deployment-branch-policies" \
      --jq '.branch_policies[] | select(.name == "v*" and .type == "tag") | .id'
  )
  if [ -z "$POLICIES" ]; then
    api_input POST \
      "repos/$REPOSITORY/environments/$ENVIRONMENT/deployment-branch-policies" \
      '{"name":"v*","type":"tag"}'
  fi
done

gh api -H "Accept: application/vnd.github+json" \
  "repos/$REPOSITORY/pages" |
  "$PYTHON_COMMAND" -c \
    'import json,sys; v=json.load(sys.stdin); assert v.get("build_type") == "workflow"'
IMMUTABLE_STATE=$(
  gh api -H "Accept: application/vnd.github+json" \
    "repos/$REPOSITORY/immutable_releases/enforcement"
)
if [ -n "$IMMUTABLE_STATE" ]; then
  printf '%s' "$IMMUTABLE_STATE" |
    "$PYTHON_COMMAND" -c \
      'import json,sys; v=json.load(sys.stdin); assert v.get("enabled") is True or v.get("state") in {"enabled","active"}'
fi
gh api -H "Accept: application/vnd.github+json" \
  "repos/$REPOSITORY/branches/$MAIN_BRANCH/protection" |
  "$PYTHON_COMMAND" -c \
    'import json,sys; v=json.load(sys.stdin); assert v["enforce_admins"]["enabled"] is True; assert v["allow_force_pushes"]["enabled"] is False; assert v["allow_deletions"]["enabled"] is False; assert "verify" in v["required_status_checks"]["contexts"]'
gh api -H "Accept: application/vnd.github+json" \
  "repos/$REPOSITORY/rulesets/$(
    gh api -H "Accept: application/vnd.github+json" \
      "repos/$REPOSITORY/rulesets" \
      --jq '.[] | select(.name == "immutable-release-tags") | .id'
  )" |
  "$PYTHON_COMMAND" -c \
    'import json,sys; v=json.load(sys.stdin); assert v["target"] == "tag" and v["enforcement"] == "active" and v.get("bypass_actors") == []; assert v["conditions"]["ref_name"]["include"] == ["refs/tags/*"]; assert {r["type"] for r in v["rules"]} == {"deletion","update"}'

for ENVIRONMENT in release promotion
do
  gh api -H "Accept: application/vnd.github+json" \
    "repos/$REPOSITORY/environments/$ENVIRONMENT" |
    "$PYTHON_COMMAND" -c \
      'import json,sys; v=json.load(sys.stdin); expected=json.loads(sys.argv[1]); rules=v["protection_rules"]; reviewers=next(r for r in rules if r["type"] == "required_reviewers"); assert reviewers["prevent_self_review"] is True; assert sorted((r["type"],r["reviewer"]["id"]) for r in reviewers["reviewers"]) == sorted((r["type"],r["id"]) for r in expected); p=v["deployment_branch_policy"]; assert p["protected_branches"] is False and p["custom_branch_policies"] is True' \
      "$REVIEWERS"
  POLICY_COUNT=$(
    gh api -H "Accept: application/vnd.github+json" \
      "repos/$REPOSITORY/environments/$ENVIRONMENT/deployment-branch-policies" \
      --jq '[.branch_policies[] | select(.name == "v*" and .type == "tag")] | length'
  )
  [ "$POLICY_COUNT" = 1 ] || {
    echo "error: $ENVIRONMENT tag deployment policy could not be verified" >&2
    exit 2
  }
done

printf 'PASS verified GitHub repository settings for %s\n' "$REPOSITORY"
