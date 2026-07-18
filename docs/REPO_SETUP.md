# Maintainer repo setup

The committed files (CI, CODEOWNERS, templates, SECURITY) define most of the
"secure and defined" story. A few things live in GitHub settings, not in the
repo — do these once after pushing.

## 1. Default token permissions

Settings → Actions → General → Workflow permissions → **Read repository contents
permission** (read-only). CI never needs write.

## 2. Branch protection (or a ruleset) on `main`

Settings → Branches → Add rule for `main`:

- [x] Require a pull request before merging
  - [x] Require approvals: **1**
  - [x] Require review from **Code Owners**
  - [x] Dismiss stale approvals when new commits are pushed
- [x] Require status checks to pass before merging
  - [x] Require branches to be up to date before merging
  - Required checks (add after the first CI run so the names resolve):
    - `python (ubuntu-latest, 3.12)` (and the other matrix combos you want to gate)
    - `js (20)`, `js (22)`
    - `e2e`
    - `zero-runtime-deps`
    - *(leave `lint + types (advisory)` NOT required until it's green, then promote)*
- [x] Require conversation resolution before merging
- [x] Do not allow bypassing the above (applies to admins too)
- [x] Block force pushes; restrict deletions

The `deps`, `e2e`, and test jobs are the security-load-bearing gates — those are
the ones that must be required.

## 3. Private vulnerability reporting

Settings → Security → **Enable** "Private vulnerability reporting". This is what
`SECURITY.md` points contributors to.

## 4. Dependabot + code scanning

Settings → Security:
- Enable Dependabot alerts and security updates (config committed in
  `.github/dependabot.yml`).
- Enable CodeQL (the committed `codeql.yml` workflow, or "Default setup").

## 5. Optional hardening

- Require signed commits (Branches → Require signed commits).
- Enable "Require a pull request" to also apply to direct pushes by you.

## Apply branch protection via gh CLI (optional)

```bash
gh api -X PUT repos/dennisbiber/interlock/branches/main/protection \
  -H "Accept: application/vnd.github+json" \
  -f "required_pull_request_reviews[require_code_owner_reviews]=true" \
  -F "required_pull_request_reviews[required_approving_review_count]=1" \
  -F "enforce_admins=true" \
  -F "restrictions=null" \
  -f "required_status_checks[strict]=true"
# then add contexts (check names) once you've seen them in the first CI run.
```
