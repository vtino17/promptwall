# Changelog

All notable changes to PromptWall are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [0.2.0] — 2026-07-28

### Added
- **Multilingual detection.** Injection, jailbreak, and system-prompt
  exfiltration patterns for **Bahasa Indonesia** — English-only filters are
  trivially bypassed by switching language.
- **Data-exfiltration-channel detector.** Flags markdown images/links whose
  URLs smuggle data to an attacker host when a UI renders them, plus a
  configurable **domain allowlist**.
- **JSON config.** `Firewall.from_config()` and the CLI `--config` flag load
  custom rules, policy, and an allowlist without writing code.
- **More secret patterns:** GitHub fine-grained tokens, npm tokens, SendGrid
  keys, and Slack webhook URLs.
- **Interactive browser demo** at `docs/index.html`, served via GitHub Pages.

### Changed
- Test suite grown to 143 offline tests.

## [0.1.0] — 2026-07-28

### Added
- Core firewall: normalization (NFKC, zero-width strip, homoglyph fold,
  base64/hex decode), six detectors (injection, jailbreak, exfiltration,
  secrets, PII, obfuscation), an explainable policy engine, and in-place
  redaction.
- Library API (`Firewall`, `scan`, `guard`), a CLI, and an MCP server.
- 99 offline tests.
