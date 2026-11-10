# Issue tracker: GitHub

Issues and PRDs for this repo live as GitHub issues. Use the [`gh`](https://cli.github.com/) CLI for all operations.

## Conventions

- **Create an issue**: `gh issue create --title "..." --body "..."`. Use a heredoc for multi-line bodies. Pass `--body-file -` to read from stdin.
- **Read an issue**: `gh issue view <number> --comments`. Use `--json ...` for machine-readable output.
- **List issues**: `gh issue list --json number,title,labels,state` with appropriate `--label` filters.
- **Comment on an issue**: `gh issue comment <number> --body "..."`.
- **Apply / remove labels**: `gh issue edit <number> --add-label "..."` / `--remove-label "..."`. Multiple labels can be comma-separated.
- **Close**: `gh issue close <number> --comment "..."`.

Infer the repo from `git remote -v` — `gh` does this automatically when run inside a clone.

## Pull requests as a triage surface

**PRs as a request surface: no.** _(Set to `yes` if this repo treats external pull requests as feature requests; `/triage` reads this flag.)_

When set to `yes`, PRs run through the same labels and states as issues, using the `gh pr` equivalents:

- **Read a PR**: `gh pr view <number> --comments` and `gh pr diff <number>` for the diff.
- **List external PRs for triage**: `gh pr list --json number,title,author,authorAssociation`, then keep only PRs whose `authorAssociation` is not `OWNER`, `MEMBER` or `COLLABORATOR` (a contributor's PR, not a maintainer's in-flight work).
- **Comment / label / close**: `gh pr comment`, `gh pr edit --add-label`/`--remove-label`, `gh pr close`.

GitHub numbers issues and PRs from one shared sequence, so `#42` is unambiguous.

## When a skill says "publish to the issue tracker"

Create a GitHub issue.

## When a skill says "fetch the relevant ticket"

Run `gh issue view <number> --comments`.
