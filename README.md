# TRACKBLOCK — Family phone stalkerware audit — MVT-class iOS/Android forensics

> Part of the **[Cognis Neural Suite](https://github.com/cognis-digital)** by [Cognis Digital](https://cognis.digital)
> MIT License · domain: `privacy`

[![PyPI](https://img.shields.io/pypi/v/cognis-trackblock.svg)](https://pypi.org/project/cognis-trackblock/)
[![CI](https://github.com/cognis-digital/trackblock/actions/workflows/ci.yml/badge.svg)](https://github.com/cognis-digital/trackblock/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Family phone stalkerware audit — MVT-class iOS/Android forensics.

## Install

```bash
pip install cognis-trackblock
```

For local development from this repo:

```bash
pip install -e .
```

## Quick start

```bash
trackblock --version
trackblock scan demos/                          # run against bundled demo
trackblock scan demos/ --format sarif --out r.sarif --fail-on high
trackblock mcp                                   # start as MCP server (Cognis.Studio / Claude Desktop / Cursor)
```

## Built-in demo scenarios

Every scenario folder includes a `SCENARIO.md` describing what it represents and what findings to expect.

- `demos/01-confirmed-stalkerware/` — see [`SCENARIO.md`](demos/01-confirmed-stalkerware/SCENARIO.md)
- `demos/02-corporate-mdm-legitimate/` — see [`SCENARIO.md`](demos/02-corporate-mdm-legitimate/SCENARIO.md)
- `demos/03-suspicious-mdm-personal/` — see [`SCENARIO.md`](demos/03-suspicious-mdm-personal/SCENARIO.md)

## How it fits the Cognis Neural Suite

This tool is one of 52 in the [Cognis Neural Suite](https://github.com/cognis-digital). The full suite + launcher lives at:

- Suite landing: https://cognis.digital
- All 52 repos: https://github.com/cognis-digital
- Cognis.Studio (Enterprise AI Workforce, MCP host): https://cognis.studio

Every Suite tool ships an MCP server, so Cognis.Studio agents can call them as scoped capabilities.

## License

MIT. See [LICENSE](LICENSE).

## About

**[Cognis Digital](https://cognis.digital)** — Wyoming, USA · *Making Tomorrow Better Today: Advanced Cybersecurity, AI Innovation, and Blockchain Expertise.*
