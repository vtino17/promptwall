# Security policy

## Supported versions

Only the latest published release receives security fixes. The default branch
and pull-request builds are development candidates, not supported releases.

## Reporting a vulnerability

Use GitHub private vulnerability reporting for this repository. Do not open a
public issue for a suspected vulnerability or include real credentials, private
prompts, or personal data in a report.

Include the affected version or commit, a minimal reproduction using synthetic
data, the expected security boundary, and the observed result. Reports are
triaged on a best-effort basis; no response-time or bounty commitment is made.

## Security boundary

PromptWall is a deterministic defense-in-depth filter, not a sandbox and not a
complete prompt-injection solution. Pattern matching can produce false positives
and false negatives. Callers remain responsible for least-privilege tool access,
authorization, output encoding, secret management, and safe failure behavior.

Custom regular expressions and configuration files are trusted operator input.
Untrusted parties must not be allowed to supply PromptWall configuration. Text
scans have a bounded default size and encoded-payload decoding has separate
size/count limits to reduce accidental resource exhaustion.
