# Branch Protection Settings

Recommended GitHub branch protection rules for `main`.

## Required Settings

### Require pull request reviews before merging

- Require at least **1 approving review**
- Dismiss stale reviews when new commits are pushed
- Require review from code owners (if `CODEOWNERS` file exists)

### Require status checks to pass before merging

Enable the following required status checks:

| Status Check              | Workflow                    |
|---------------------------|-----------------------------|
| `pytest (py3.12)`         | Tests & Coverage            |
| `pytest (py3.13)`         | Tests & Coverage            |
| `Ruff lint & format check`| Lint & Static Analysis     |
| `Run pre-commit hooks`    | Pre-commit Checks           |

- **Require branches to be up to date before merging** — ensures the PR is
  tested against the latest `main` before it can land.

### Restrict force pushes

- **Do not allow force pushes** to `main`. Force pushes rewrite history and
  can break other contributors' branches.

### Additional recommendations

- **Do not allow deletions** — prevent accidental deletion of `main`.
- **Require linear history** (optional) — enforces squash or rebase merges
  for a cleaner commit log.
- **Require signed commits** (optional) — adds an extra layer of commit
  authenticity verification.

## Applying These Settings

1. Go to **Settings > Branches** in the GitHub repository.
2. Click **Add branch protection rule**.
3. Set **Branch name pattern** to `main`.
4. Enable the settings listed above.
5. Click **Create** (or **Save changes**).
