# Git and GitHub workflow

## Repository policy

- Default branch: `main`.
- Work branches: `feature/socplat-XXX-short-description` or
  `fix/socplat-XXX-short-description`.
- Commit style: Conventional Commits.
- Merge through a pull request after CI passes.
- Prefer squash merge for a small pull request whose intermediate commits do
  not add useful history; otherwise preserve well-structured commits.

For a personal project, issues plus pull requests provide enough traceability.
GitHub Projects, mandatory reviewers, and multiple release branches are not
needed during Sprint 1.

## First publication

Configure your real author identity locally if it is not already configured:

```powershell
git config user.name "Your Name"
git config user.email "your-github-email@example.com"
```

Build a small initial history instead of one catch-all commit:

```powershell
git add .gitignore .python-version pyproject.toml uv.lock
git commit -m "chore: initialize uv Python project"

git add src data/security_events.jsonl
git commit -m "feat: add core authentication detection pipeline"

git add tests
git commit -m "test: cover brute force detection pipeline"

git add README.md docs CONTRIBUTING.md SECURITY.md .github
git commit -m "docs: document Sprint 1 and repository workflow"
```

Create an empty repository on GitHub without generating a README, `.gitignore`,
or license there, then connect and push this existing history:

```powershell
git remote add origin https://github.com/<owner>/ForgeSOC.git
git push -u origin main
```

Before pushing, confirm that no generated or sensitive files are included:

```powershell
git status
git ls-files
git grep -n -i -E "api[_-]?key|password|secret|token"
```

Review matches manually because synthetic event text and security documentation
may contain harmless words such as `password` or `secret`.

## Public or private

Starting privately is useful while identity, history, and documentation are
being cleaned up. Once this baseline has been reviewed, making it public gives
the portfolio project visibility. Before changing visibility, confirm again
that all telemetry is synthetic and the complete Git history contains no
secrets.

## Repository settings after the first push

1. Enable the Actions workflow and confirm CI passes.
2. Protect `main`: require pull requests and the `quality` status check.
3. Enable secret scanning and dependency alerts when available.
4. Create the Sprint 2 milestone only when its scope is agreed.
5. Add a license only after deliberately choosing its reuse terms.

Tags and releases should begin when ForgeSOC has a coherent demonstrable
milestone. Sprint 1 can later become `v0.1.0`; creating that tag is optional
until the repository has been reviewed on GitHub.
