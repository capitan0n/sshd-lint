# sshd_lint

A zero-dependency static analyzer for OpenSSH `sshd_config` files. Audits configs
offline — no root, no network, no live server needed.

`sshd_lint` evaluates your SSH server configuration against industry-standard security baselines, including the **CIS Benchmark for Linux**, **Mozilla OpenSSH Guidelines**, and **NIST SP 800-53**.

---

## 💡 Motivation

This project was born out of a recurring practical need: quickly auditing an SSH server configuration whenever setting up a new test VM or reviewing a production host.

Existing tools either require root on the live system or an open network connection to the server. `sshd_lint` takes the opposite approach — it reads the config file and nothing else, which means it works on a copy pulled from a machine you cannot log into, inside a container image, or in a CI pipeline where no SSH server is running at all.

---

## 🤖 AI-Assisted Project

This tool was conceptualized and developed with the assistance of Artificial Intelligence.  
AI was used for code generation, logic refinement, and edge-case handling (such as cumulative directives and `Match` block scoping), under human direction and review.

---

## ✨ Features

- **Zero Dependencies** — Built entirely on the Python standard library. No `pip install`.
- **Context-Aware Parsing** — Understands OpenSSH semantics: `Match` blocks, `Match All` reset, directive shadowing, and `Include` glob expansion.
- **Scoped Match Block Findings** — Distinguishes between global misconfigurations and risks that apply only to specific users, addresses, or groups.
- **Duplicate Directive Detection** — Warns when a directive appears more than once globally, since sshd silently uses only the first occurrence.
- **Detailed, Actionable Reports** — Explains what is wrong, why it matters, and references the relevant standard.
- **CI/CD Ready** — Structured JSON output, and exit codes that separate a security verdict from an operational failure.
- **Version-Aware Rules** — Adjusts expectations based on target OpenSSH version.

---

## 📦 Requirements

- Python **3.9+**
- No external packages

---

## ⚙️ Installation

Since there are no external dependencies, you can run it directly:

```bash
wget https://raw.githubusercontent.com/capitan0n/sshd-lint/main/sshd_lint.py -O sshd_lint
chmod +x sshd_lint
./sshd_lint
```

Or clone the repository:

```bash
git clone https://github.com/capitan0n/sshd-lint.git
cd sshd-lint
python sshd_lint.py
```

---

## 📋 Sample Output

```
$ sshd_lint /etc/ssh/sshd_config --severity medium --compact

sshd_lint 1.4.0 — /etc/ssh/sshd_config
────────────────────────────────────────────────────────────
Findings: 5  CRITICAL: 1  HIGH: 1  MEDIUM: 3
────────────────────────────────────────────────────────────

[CRITICAL] PermitRootLogin (line 2)
  Current value : yes
  Issue         : Root login over SSH is permitted.

[HIGH] PasswordAuthentication (line 3)
  Current value : yes
  Issue         : Password authentication is enabled.

[MEDIUM] MaxAuthTries (line 5)
  Current value : 8
  Issue         : MaxAuthTries is 8 — recommended ≤ 4.

[MEDIUM] AllowUsers / AllowGroups
  Current value : <not set>
  Issue         : No user or group allowlist is defined.

[MEDIUM] X11Forwarding (line 4)
  Current value : yes
  Issue         : X11 forwarding is enabled.
```

Without `--compact`, each finding also carries a **Why it matters** explanation and the
standards it references. Colors are enabled automatically when writing to a terminal and
disabled when piping or redirecting.

---

## 🚀 Usage

Analyze the default system SSH config:

```bash
python sshd_lint.py
```

Analyze a specific file:

```bash
python sshd_lint.py /path/to/sshd_config
```

Filter by severity (only HIGH and above):

```bash
python sshd_lint.py --severity high
```

Compact output (hides explanations — useful for quick scans):

```bash
python sshd_lint.py --compact
```

JSON output for pipeline integration:

```bash
python sshd_lint.py --format json
```

The JSON output is self-contained — `exit_code` and a per-severity `summary` are included at the top level so consumers don't need to capture `$?` separately:

```json
{
  "exit_code": 2,
  "summary": {
    "CRITICAL": 1,
    "HIGH": 1,
    "MEDIUM": 0,
    "LOW": 0,
    "INFO": 0
  },
  "findings": [
    {
      "severity": "HIGH",
      "directive": "PasswordAuthentication",
      "value": "yes",
      "line": 3,
      "scope": "global",
      "message": "Password authentication is enabled.",
      "detail": "Password authentication is vulnerable to brute-force and credential-stuffing attacks. Disable it and use public-key authentication exclusively: 'PasswordAuthentication no'.",
      "references": ["CIS Benchmark for Linux", "Mozilla OpenSSH Guidelines"]
    }
  ]
}
```

Note that `exit_code` in the JSON only ever carries the findings verdict (`0`, `1` or `2`).
Operational failures — a bad flag or a missing config file — produce no JSON at all, so a
document that parses is always a real report.

Filter with `jq`:

```bash
# Only CRITICAL findings
python sshd_lint.py --format json | jq '.findings[] | select(.severity == "CRITICAL")'

# Summary only
python sshd_lint.py --format json | jq '.summary'

# Read exit code from JSON instead of $?
python sshd_lint.py --format json | jq '.exit_code'
```

Audit a config copied from a remote server, resolving Includes from the live system:

```bash
scp user@server:/etc/ssh/sshd_config /tmp/audit/sshd_config
python sshd_lint.py /tmp/audit/sshd_config --base-dir /etc/ssh
```

---

## 🧰 CLI Flags

| Flag                  | Short | Description |
|-----------------------|-------|-------------|
| `config`              | —     | Path to sshd_config (default: `/etc/ssh/sshd_config`) |
| `--severity`          | `-s`  | Minimum severity: `critical`, `high`, `medium`, `low`, `info` (default: `info`) |
| `--format`            | `-f`  | Output format: `text` or `json` (default: `text`) |
| `--compact`           | `-c`  | Hide explanations and references for cleaner output |
| `--no-color`          | —     | Disable ANSI colors |
| `--openssh-version`   | —     | Target OpenSSH version (e.g. `8.9`) for version-aware rule adjustments |
| `--base-dir`          | —     | Base directory for `Include` resolution. Default: same directory as the config file |
| `--help`              | `-h`  | Show usage and exit |
| `--version`           | `-V`  | Show version and exit |

> `-V` is used for `--version` so that `-v` stays free for a future verbosity flag,
> following the common convention where `-v` means verbose.

---

## 🚦 Exit Codes

Exit codes fall into two groups. `0`–`2` are the **security verdict**; `64` and `66`
signal that the tool could not run at all. Keeping them separate means a typo in a flag
can never be mistaken by a pipeline for a critical finding.

| Code | Meaning |
|------|---------|
| `0`  | No findings at or above the requested severity threshold |
| `1`  | Findings exist, but none are HIGH or CRITICAL |
| `2`  | At least one HIGH or CRITICAL finding — pipeline should fail |
| `64` | Usage error — unrecognized flag or invalid argument (`EX_USAGE`) |
| `66` | Config file not found or unreadable (`EX_NOINPUT`) |

`64` and `66` follow the conventional values from BSD `sysexits.h`.

When using `--format json`, the verdict is also embedded in the JSON output as
`exit_code`, so the report is fully self-contained and readable by downstream tools
without capturing `$?`.

### GitHub Actions

CI systems treat **any** non-zero exit code as failure, which would collapse the
distinction between `1` and `2`. Translate the verdict explicitly:

```yaml
- name: Lint SSH config
  run: |
    code=0
    python sshd_lint.py /etc/ssh/sshd_config --format json > report.json || code=$?
    cat report.json
    # Fail only on HIGH/CRITICAL. Exit 1 = minor findings, informational.
    if [ "$code" -ge 2 ]; then
      echo "::error::HIGH or CRITICAL findings in sshd_config"
      exit 1
    fi
```

`|| code=$?` does two jobs: it captures the exit code, and it stops `bash -e` (the default
shell for `run:` steps) from aborting the script the moment the linter returns non-zero.
`cat` must come *after* the capture, since `$?` only holds the status of the most recent
command.

---

## 🧪 Rules Evaluated

### Parse & File Handling
- Rule 00: Include resolution problems — unreadable files, an Include glob matching
  more than 500 files (refused outright), an Include glob matching 0 files, and lines
  that couldn't be parsed as a directive

### Authentication
- Rule 01: `PermitRootLogin`
- Rule 02: `PasswordAuthentication`
- Rule 03: `PermitEmptyPasswords`
- Rule 04: `ChallengeResponseAuthentication`
- Rule 05: `PubkeyAuthentication`
- Rule 06: `HostbasedAuthentication` / `IgnoreRhosts`

### Access Control
- Rule 10: `LoginGraceTime`
- Rule 11: `MaxAuthTries`
- Rule 12: `MaxSessions`
- Rule 13: `MaxStartups`
- Rule 14: `AllowUsers` / `AllowGroups`

### Forwarding & Tunneling
- Rule 20: `X11Forwarding`
- Rule 21: `AllowTcpForwarding`
- Rule 22: `AllowAgentForwarding`
- Rule 23: `GatewayPorts`
- Rule 24: `PermitTunnel`

### Logging & Auditing
- Rule 30: `LogLevel`
- Rule 31: `PrintLastLog`

### Cryptography
- Rule 40: Weak or deprecated Ciphers
- Rule 41: Weak or deprecated MACs
- Rule 42: Weak KexAlgorithms (key exchange)
- Rule 43: Deprecated HostKeyAlgorithms
- Rule 44: Deprecated `PubkeyAcceptedAlgorithms`

Rules 40-44 understand OpenSSH's `+`/`-`/`^` default-set syntax (e.g. `Ciphers +arcfour`
appends to the compiled-in default rather than replacing it) — a weak algorithm is flagged
whether it fully replaces the list or is merely appended to it.

### Miscellaneous
- Rule 50: `Banner`
- Rule 51: `StrictModes`
- Rule 52: `Port` (default port 22)
- Rule 53: `ClientAliveInterval` / idle session timeout
- Rule 54: `UseDNS`
- Rule 55: Insecure directives inside `Match` blocks (scoped risk)
- Rule 56: Duplicate global directives (shadowed by sshd)
- Rule 57: `PermitUserEnvironment`

---

## 🔍 How sshd_lint differs from similar tools

| Tool | How it works | Requires root / live system |
|------|--------------|-----------------------------|
| **Lynis** | Runs live on the system, audits many aspects | Yes |
| **ssh-audit** | Connects to a live SSH server, tests its responses | Yes (network access) |
| **sshd_lint** | Reads the config file statically, offline | No |

`sshd_lint` is designed for offline auditing, CI/CD pipelines, and reviewing configs from remote systems without needing access to the live server.

---

## ⚠️ Limitations

- **Static analysis only** — does not connect to a live server or test actual behaviour.
- **Match block conditions are not evaluated** — the condition string (e.g. `User anoncvs`, `Address 10.0.0.0/8`) is recorded and reported, but sshd_lint cannot determine whether it applies to a given connection.
- **Include resolution requires filesystem access** — unreadable files and Include
  globs matching over 500 files are reported as CRITICAL; a glob matching 0 files is
  reported as INFO (often benign — e.g. an empty `sshd_config.d/` — but worth a glance).
- **Relative `Include` paths resolve against `--base-dir` / the config file's own
  directory, not real sshd's hardcoded `/etc/ssh`.** For the common case of auditing
  the live `/etc/ssh/sshd_config` these are identical. When auditing a copy of only the
  main file (without its snippets alongside it), pass `--base-dir /etc/ssh` to resolve
  includes the way sshd itself would.
- **Version-aware rules are currently minimal** — the `--openssh-version` flag adjusts a small number of known defaults; more version-specific rules may be added in future releases.
- **Compiled-in defaults are for OpenSSH 8.x** — behaviour on significantly older or newer versions may differ.

---

## Author

* **capitan0n** - [capitan0n](https://github.com/capitan0n)

---

## 📜 License

MIT License
