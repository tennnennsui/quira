# Contributing to Quira

Thank you for your interest in contributing to Quira! This guide will help you get started.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By participating, you agree to uphold this code. Report unacceptable behavior to conduct@quira.com.

## Quick Start

```bash
git clone https://github.com/YOUR_USERNAME/quira.git
cd quira
just setup    # Install all dependencies
just dev      # Run in development mode
just test     # Run tests
just lint     # Run linters
just format   # Auto-format code
```

## Development Setup

### Prerequisites
- Git
- Rust (latest stable)
- Node.js 20+
- [Just](https://github.com/casey/just): `cargo install just`

### Dev Container
If you use VS Code: install "Dev Containers" extension, open the project, and click "Reopen in Container". Everything is pre-configured.

## Finding Work

We maintain **15-20 issues** labeled [`good first issue`](https://github.com/tennnennsui/quira/labels/good%20first%20issue) at all times.

| Label | Meaning |
|-------|---------|
| `good first issue` | Great for new contributors |
| `beginner` / `intermediate` / `advanced` | Difficulty level |
| `ui` / `graph-engine` / `ai` / `spaces` / `docs` | Area |
| `help wanted` | Community help welcome |

Each good-first-issue has an assigned **mentor** for questions.

### RFCs
Large changes require an RFC via [GitHub Discussions](https://github.com/tennnennsui/quira/discussions) with a 2-week review period.

## Pull Request Process

1. Fork the repo and create a branch: `feat/your-feature`, `fix/your-fix`
2. Write tests for new functionality
3. Fill out the PR template completely
4. Link related issues (e.g., "Closes #123")
5. All CI checks must pass

**Review SLA:** First review within 24 hours.

After merge, first-time contributors are automatically added to CONTRIBUTORS.md.

## Coding Standards

### Rust
- `rustfmt` + `clippy` (all warnings resolved)
- `Result<T, E>` over panics
- Doc comments for public APIs

### TypeScript
- ESLint + Prettier (config provided)
- Strict mode, no `any` without justification

### General
- Immutable data patterns preferred
- Functions < 50 lines, files < 800 lines

## Commit Messages

[Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add Context Graph date filtering
fix: resolve Space switch animation stutter
docs: update build instructions for Apple Silicon
```

### Sign-off (DCO)

We use the [Developer Certificate of Origin](https://developercertificate.org/):

```bash
git commit -s -m "feat: your feature"
```

## Contributor Levels

| Level | Requirements | Permissions |
|-------|-------------|-------------|
| Contributor | 1+ merged PR | Submit PRs, comment |
| Trusted Contributor | 5+ PRs + 3 months active | Triage issues, labels |
| Maintainer | 10+ PRs + nomination | Merge PRs, review |
| Core Team | Steering Committee approval | Release authority |

## Getting Help

- **Discord**: [#development](https://discord.gg/quira)
- **GitHub Discussions**: [Q&A](https://github.com/tennnennsui/quira/discussions)
- **Issue mentors**: Each good-first-issue has an assigned mentor

---

Thank you for helping build the future of browsing.
