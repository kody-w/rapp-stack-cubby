#!/bin/sh
set -eu

REPOSITORY=
MAIN_BRANCH=main
REVIEWER_USER_ID=
REVIEWER_TEAM_ID=
SOLE_OWNER=false

while [ "$#" -gt 0 ]; do
  case "$1" in
    --repo) REPOSITORY=$2; shift 2 ;;
    --main-branch) MAIN_BRANCH=$2; shift 2 ;;
    --reviewer-user-id) REVIEWER_USER_ID=$2; shift 2 ;;
    --reviewer-team-id) REVIEWER_TEAM_ID=$2; shift 2 ;;
    --sole-owner) SOLE_OWNER=true; shift ;;
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
if [ "$SOLE_OWNER" = true ]; then
  if [ -n "$REVIEWER_USER_ID" ] || [ -n "$REVIEWER_TEAM_ID" ]; then
    echo "error: --sole-owner cannot be combined with reviewer IDs" >&2
    exit 2
  fi
  REVIEWER_MODE=sole-owner
else
  if [ -z "$REVIEWER_USER_ID" ] && [ -z "$REVIEWER_TEAM_ID" ]; then
    echo "error: strict reviewer mode requires an explicit reviewer ID" >&2
    exit 2
  fi
  REVIEWER_MODE=strict
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
API_VERSION=2022-11-28

gh_api() {
  gh api \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: $API_VERSION" \
    "$@"
}

api_input() {
  METHOD=$1
  ENDPOINT=$2
  PAYLOAD=$3
  printf '%s\n' "$PAYLOAD" |
    gh_api --method "$METHOD" \
      "$ENDPOINT" --input - >/dev/null
}

gh_api "repos/$REPOSITORY" >/dev/null

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

IMMUTABLE_ENDPOINT_SUPPORTED=false
if IMMUTABLE_PROBE=$(
  gh_api --include \
    "repos/$REPOSITORY/immutable_releases/enforcement" 2>&1
); then
  IMMUTABLE_ENDPOINT_SUPPORTED=true
else
  IMMUTABLE_PROBE_EXIT=$?
  IMMUTABLE_HTTP_STATUS=$(
    printf '%s\n' "$IMMUTABLE_PROBE" |
      awk '$1 ~ /^HTTP\// && $2 ~ /^[0-9][0-9][0-9]$/ { status=$2 } END { print status }'
  )
  if [ "$IMMUTABLE_HTTP_STATUS" != 404 ]; then
    printf '%s\n' "$IMMUTABLE_PROBE" >&2
    echo "error: immutable-releases API probe failed (HTTP ${IMMUTABLE_HTTP_STATUS:-unknown}, exit $IMMUTABLE_PROBE_EXIT)" >&2
    exit 2
  fi
fi
if [ "$IMMUTABLE_ENDPOINT_SUPPORTED" = true ]; then
  gh_api --method PUT \
    "repos/$REPOSITORY/immutable_releases/enforcement" >/dev/null
fi

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
  gh_api \
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
    "prevent_self_review": bool(json.loads(sys.argv[1])),
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
    gh_api \
      "repos/$REPOSITORY/environments/$ENVIRONMENT/deployment-branch-policies" \
      --jq '.branch_policies[] | select(.name == "v*" and .type == "tag") | .id'
  )
  if [ -z "$POLICIES" ]; then
    api_input POST \
      "repos/$REPOSITORY/environments/$ENVIRONMENT/deployment-branch-policies" \
      '{"name":"v*","type":"tag"}'
  fi
done

gh_api "repos/$REPOSITORY/pages" |
  "$PYTHON_COMMAND" -c \
    'import json,sys; v=json.load(sys.stdin); assert v.get("build_type") == "workflow"'
if [ "$IMMUTABLE_ENDPOINT_SUPPORTED" = true ]; then
  IMMUTABLE_STATE=$(
    gh_api \
    "repos/$REPOSITORY/immutable_releases/enforcement"
  )
  printf '%s' "$IMMUTABLE_STATE" |
    "$PYTHON_COMMAND" -c \
      'import json,sys; v=json.load(sys.stdin); assert v.get("enabled") is True'
fi
gh_api "repos/$REPOSITORY/branches/$MAIN_BRANCH/protection" |
  "$PYTHON_COMMAND" -c \
    'import json,sys; v=json.load(sys.stdin); assert v["enforce_admins"]["enabled"] is True; assert v["allow_force_pushes"]["enabled"] is False; assert v["allow_deletions"]["enabled"] is False; assert "verify" in v["required_status_checks"]["contexts"]'
VERIFIED_RULESET_IDS=$(
  gh_api "repos/$REPOSITORY/rulesets" \
    --jq '.[] | select(.name == "immutable-release-tags") | .id'
)
case "$VERIFIED_RULESET_IDS" in
  '') echo "error: immutable-release-tags ruleset is missing" >&2; exit 2 ;;
  *'
'*) echo "error: duplicate immutable tag rulesets exist" >&2; exit 2 ;;
esac
gh_api "repos/$REPOSITORY/rulesets/$VERIFIED_RULESET_IDS" |
  "$PYTHON_COMMAND" -c \
    'import json,sys; v=json.load(sys.stdin); rules=v.get("rules"); assert v.get("name") == "immutable-release-tags" and v.get("target") == "tag" and v.get("enforcement") == "active" and v.get("bypass_actors") == []; assert v.get("conditions", {}).get("ref_name", {}).get("include") == ["refs/tags/*"]; assert v.get("conditions", {}).get("ref_name", {}).get("exclude") == []; assert isinstance(rules, list) and len(rules) == 2 and sorted(r.get("type") for r in rules) == ["deletion","update"]'

for ENVIRONMENT in release promotion
do
  gh_api "repos/$REPOSITORY/environments/$ENVIRONMENT" |
    "$PYTHON_COMMAND" -c \
      'import json,sys
v=json.load(sys.stdin)
expected=json.loads(sys.argv[1])
strict=sys.argv[2] == "strict"
required=[r for r in v["protection_rules"] if r["type"] == "required_reviewers"]
assert len(required) == (1 if strict else 0)
if strict:
    reviewers=required[0]
    assert reviewers["prevent_self_review"] is True
    assert sorted((r["type"],r["reviewer"]["id"]) for r in reviewers["reviewers"]) == sorted((r["type"],r["id"]) for r in expected)
p=v["deployment_branch_policy"]
assert p["protected_branches"] is False and p["custom_branch_policies"] is True' \
      "$REVIEWERS" "$REVIEWER_MODE"
  POLICY_COUNT=$(
    gh_api \
      "repos/$REPOSITORY/environments/$ENVIRONMENT/deployment-branch-policies" \
      --jq '[.branch_policies[] | select(.name == "v*" and .type == "tag")] | length'
  )
  [ "$POLICY_COUNT" = 1 ] || {
    echo "error: $ENVIRONMENT tag deployment policy could not be verified" >&2
    exit 2
  }
done

printf 'PASS verified GitHub repository settings for %s\n' "$REPOSITORY"
