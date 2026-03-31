<div align="center">

# Quira Browser

**Ask your browser anything.**

Your browsing context, structured by local AI. Private by design.

[Download](#installation) · [Roadmap](ROADMAP.md) · [Contributing](CONTRIBUTING.md) · [Discord](https://discord.gg/quira)

</div>

---

## What is Quira?

Quira is an open-source browser that remembers your browsing context and lets you query it with natural language — all processed locally on your device.

ChatGPT knows the internet. **Quira knows YOU.**

Every page you visit becomes a node in your personal **Context Graph** — a visual map of your research trails, connections, and insights. Ask Quira what you read last Tuesday, resume a research session from weeks ago, or get a summary of everything you've explored on a topic. Your data never leaves your device.

## Core Features

### Context Graph
Your browsing history, automatically structured as an interactive knowledge graph. See how topics connect, discover patterns in your research, and never lose a trail of thought.

### Ask Your Browser Anything
Natural language queries over your personal browsing context. *"What was that CSS grid article I read on Thursday?"* — Quira answers with the exact page, your reading time, and related nodes. Every answer cites its source. Zero hallucination.

### Context Spaces
Reinvented tab management. Group tabs into dedicated workspaces — one for each project, research topic, or area of life. Switch contexts instantly. Each Space has its own color, personality, and memory.

### Research Replay
Pick up any research session exactly where you left off. Quira detects research clusters in your Context Graph and lets you resume with one click — tabs restored, context refreshed, AI summary of where you stopped.

### Local-First AI
All AI processing runs on your device using lightweight models (Phi-3.5 Mini / Llama 3.1 8B). Your data stays yours. Optional cloud AI is available as an opt-in — with full transparency about what gets sent.

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Browser Engine | Gecko (Mozilla) |
| Local LLM Runtime | llama.cpp / MLX (Apple Silicon) |
| Graph Storage | SQLite + Vector DB |
| Graph Rendering | WebGPU |
| Core Language | Rust + TypeScript |

## Installation

> Quira is in active development. Alpha builds will be available in Q2 2026.

### Supported Platforms (Alpha)
- Linux (x86_64)
- macOS (Apple Silicon + Intel)
- Windows support planned for Phase 3

### Minimum Requirements
| | Minimum | Recommended |
|---|---------|-------------|
| RAM | 8GB | 16GB |
| CPU | 4 cores | 8 cores |
| Storage | 2GB free | 5GB free |

### Build from Source

```bash
git clone https://github.com/tennnennsui/quira.git
cd quira
just setup    # Install dependencies + build
just dev      # Run in development mode
just test     # Run all tests
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed development setup.

## Roadmap

See [ROADMAP.md](ROADMAP.md) for the full timeline.

| Phase | Timeline | Milestone |
|-------|----------|-----------|
| Alpha | Apr-Jun 2026 | Context Spaces + Local AI + Context Graph |
| Beta | Jul-Aug 2026 | NL Query + Research Replay + Public beta |
| v1.0 | Sep 2026 | Stable release |
| v2.0 | Q4 2026 | Pro tier + Sync + Enterprise |

## Privacy

- **Your browsing history stays on your device.** Always.
- **Your Context Graph stays on your device.** It is never uploaded.
- **AI processing is local by default.** Cloud AI is opt-in with clear indication of what is sent.
- **Telemetry is opt-in and anonymous.** No personal data, no browsing data.

Your browsing context is the most personal data you have. We will never monetize it.

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) to get started.

We maintain 15-20 [good first issues](https://github.com/tennnennsui/quira/labels/good%20first%20issue) at all times.

## Community

- **Discord**: [discord.gg/quira](https://discord.gg/quira)
- **GitHub Discussions**: [Questions & ideas](https://github.com/tennnennsui/quira/discussions)
- **Twitter/X**: [@QuiraBrowser](https://x.com/QuiraBrowser)
- **Blog**: [quira.com/blog](https://quira.com/blog)

## License

Quira Browser is open source under multiple licenses:

| Component | License |
|-----------|---------|
| Browser shell (Gecko fork) | [MPL-2.0](LICENSE) |
| Context Graph engine | AGPL-3.0 |
| Local AI runtime | Apache-2.0 |
| Plugin API | Apache-2.0 |

See [LICENSE](LICENSE) for the MPL-2.0 text.

---

<div align="center">

**Your browsing. Your AI. Your device.**

*Quira — Ask your browser anything.*

</div>
