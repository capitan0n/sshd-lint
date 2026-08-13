# sshd_lint

A zero-dependency static analyzer for OpenSSH `sshd_config` files. It audits a
configuration offline — no root, no network, and no running SSH server required.

`sshd_lint` reads the configuration file and nothing else. That makes it usable on a copy
pulled from a machine you cannot log into, inside a container image, or in a CI pipeline
where no SSH server is running at all.

---

## Motivation

The tool grew out of a recurring practical need: quickly auditing an SSH server
configuration when setting up a new test VM or reviewing a production host.

Existing tools either require root on the live system or an open network connection to the
server. `sshd_lint` takes the opposite approach — static analysis of the configuration text,
with enough parsing fidelity to model the parts of OpenSSH's semantics that actually bite:
`Match` scoping, `Include` expansion, and first-wins directive shadowing.

---

## Features

- **Zero runtime dependencies.** Built entirely on the Python standard library. Installs
  with a single `pip install`, then runs with nothing else.
- **Context-aware parsing.** Understands OpenSSH semantics: `Match` blocks, `Match All`
  reset, directive shadowing, cumulative directives, and `Include` glob expansion.
- **Match state threaded through includes.** An `Include` inside a `Match` block is analyzed
  under that block, and a `Match` opened inside an included file stays open after control
  returns — mirroring how sshd itself behaves.
- **Findings are located, not just numbered.** Every finding carries the file it came from,
  so a line number still means something once `Include` is in play.
- **Scoped Match block findings.** Distinguishes global misconfigurations from risks that
  apply only to specific users, addresses, or groups.
- **Duplicate directive detection.** Warns when a directive is silently shadowed, with
  cumulative directives correctly excluded.
- **No silent skips.** A value the linter cannot interpret is reported as a finding rather
  than passing quietly. A clean report means *checked*, not *skipped*.
- **CI/CD ready.** Structured JSON output, and exit codes that separate a security verdict
  from an operational failure.
- **Version-aware rules.** Adjusts expectations based on the target OpenSSH version.

---

## Requirements

- Python 3.9 or newer
- No external packages — the standard library only
- Linux or BSD (the tool relies on POSIX conventions; Windows is not supported)

---

## Installation

### Via pip (recommended)

```bash
pip install sshd-lint
```

This installs the `sshd-lint` command on your `PATH`:

```bash
sshd-lint /etc/ssh/sshd_config
```

On distributions that enforce [PEP 668](https://peps.python.org/pep-0668/) (Arch, Debian,
Fedora), install into a virtual environment or use [pipx](https://pipx.pypa.io/):

```bash
pipx install sshd-lint
```

### From source (for development)

```bash
git clone https://github.com/capitan0n/sshd-lint.git
cd sshd-lint
pip install -e .
sshd-lint /etc/ssh/sshd_config
```

Or run it as a module without installing:

```bash
git clone https://github.com/capitan0n/sshd-lint.git
cd sshd-lint/src
python -m sshd_lint /etc/ssh/sshd_config
```

---

## Sample Output

```
$ sshd-lint samples/realistic.conf --severity medium --compact

sshd_lint 1.5.0 — /path/to/samples/realistic.conf
────────────────────────────────────────────────────────────
Findings: 5  HIGH: 1  MEDIUM: 4
────────────────────────────────────────────────────────────

[HIGH] PasswordAuthentication (line 26)
  Current value : yes
  Issue         : Password authentication is enabled.

[MEDIUM] PermitRootLogin (line 22)
  Current value : prohibit-password
  Issue         : Root login is allowed with a public key (no password required).

[MEDIUM] MaxAuthTries
  Current value : 6
  Issue         : MaxAuthTries is 6 — recommended ≤ 4.

[MEDIUM] AllowUsers / AllowGroups
  Current value : <not set>
  Issue         : No user or group allowlist is defined.

[MEDIUM] X11Forwarding (line 33)
  Current value : yes
  Issue         : X11 forwarding is enabled.
```

A directive with no line number is not set in the configuration — the finding concerns the
compiled-in default that applies in its absence.

Without `--compact`, each finding also carries a *Why it matters* explanation and the
standards it references:

```
[HIGH] PasswordAuthentication (line 26)
  Current value : yes
  Issue         : Password authentication is enabled.
  Why it matters: Password authentication is vulnerable to brute-force and
                  credential-stuffing attacks. Disable it and use public-key
                  authentication exclusively: 'PasswordAuthentication no'.
  References    : CIS Benchmark for Linux | Mozilla OpenSSH Guidelines
```

Colors are enabled automatically when writing to a terminal and disabled when piping or
redirecting.

---

## Match Blocks and Includes

Most real configurations are split across an `sshd_config.d/` directory. `sshd_lint` expands
those includes and tracks where each directive actually came from:

```
$ sshd-lint /etc/ssh/sshd_config --severity high --compact

[HIGH] PasswordAuthentication (/etc/ssh/sshd_config.d/50-cloud.conf:2) [Match: User ansible]
  Current value : yes
  Issue         : Match block [User ansible] sets PasswordAuthentication yes —
                  allows password login for matched connections, bypassing the global 'no'.
```

Two behaviours are worth knowing, because both mirror real sshd semantics rather than
intuition:

- An `Include` **inside** a `Match` block is processed under that block. Directives in the
  included file inherit the scope.
- A `Match` opened **inside** an included file stays open after the include returns, and so
  scopes the remainder of the parent file. This is a genuine OpenSSH footgun, and it is why
  distributions place the `Include sshd_config.d/*.conf` line at the very **top** of
  `sshd_config`, before any `Match` block can be active.

---

## Usage

```bash
sshd-lint                                  # analyze /etc/ssh/sshd_config
sshd-lint /path/to/sshd_config             # analyze a specific file
sshd-lint --severity high                  # only HIGH and above
sshd-lint --compact                        # hide explanations
sshd-lint --format json                    # machine-readable output
```

The JSON output is self-contained — `exit_code` and a per-severity `summary` sit at the top
level, so consumers do not need to capture `$?` separately:

```json
{
  "exit_code": 2,
  "summary": {
    "CRITICAL": 0,
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
      "file": "/etc/ssh/sshd_config",
      "line": 26,
      "scope": "global",
      "message": "Password authentication is enabled.",
      "detail": "Password authentication is vulnerable to brute-force and credential-stuffing attacks. Disable it and use public-key authentication exclusively: 'PasswordAuthentication no'.",
      "references": ["CIS Benchmark for Linux", "Mozilla OpenSSH Guidelines"]
    }
  ]
}
```

`file` is `null` when a finding concerns a directive that is not present in the
configuration. `exit_code` only ever carries the findings verdict (`0`, `1`, or `2`);
operational failures produce no JSON at all, so a document that parses is always a real
report.

Filter with `jq`:

```bash
sshd-lint --format json | jq '.findings[] | select(.severity == "CRITICAL")'
sshd-lint --format json | jq '.summary'
sshd-lint --format json | jq -r '.findings[] | "\(.file // "default"):\(.line // 0) \(.directive)"'
```

Audit a configuration copied from a remote server, resolving includes from the live system:

```bash
scp user@server:/etc/ssh/sshd_config /tmp/audit/sshd_config
sshd-lint /tmp/audit/sshd_config --base-dir /etc/ssh
```

---

## CLI Flags

| Flag                  | Short | Description |
|-----------------------|-------|-------------|
| `config`              | —     | Path to sshd_config (default: `/etc/ssh/sshd_config`) |
| `--severity`          | `-s`  | Minimum severity: `critical`, `high`, `medium`, `low`, `info` (default: `info`) |
| `--format`            | `-f`  | Output format: `text` or `json` (default: `text`) |
| `--compact`           | `-c`  | Hide explanations and references for cleaner output |
| `--no-color`          | —     | Disable ANSI colors |
| `--openssh-version`   | —     | Target OpenSSH version (e.g. `8.9`) for version-aware rule adjustments |
| `--base-dir`          | —     | Base directory for `Include` resolution (default: the config file's own directory) |
| `--help`              | `-h`  | Show usage and exit |
| `--version`           | `-V`  | Show version and exit |

`-V` is used for `--version` so that `-v` remains free for a future verbosity flag,
following the common convention where `-v` means verbose. The
[`NO_COLOR`](https://no-color.org/) environment variable is honoured as an alternative to
`--no-color`.

---

## Exit Codes

Exit codes fall into three groups. `0`–`2` are the **security verdict**; `64` and `66`
signal that the tool could not run at all; `130` and `141` are ordinary shell terminations.
Keeping them separate means a typo in a flag, an unreadable file, or a closed pipe can never
be mistaken by a pipeline for a critical finding.

| Code  | Meaning |
|-------|---------|
| `0`   | No findings at or above the requested severity threshold |
| `1`   | Findings exist, but none are HIGH or CRITICAL |
| `2`   | At least one HIGH or CRITICAL finding — the pipeline should fail |
| `64`  | Usage error — unrecognized flag or invalid argument (`EX_USAGE`) |
| `66`  | Config file missing, unreadable, or not a regular file (`EX_NOINPUT`) |
| `130` | Interrupted with Ctrl-C (128 + SIGINT) |
| `141` | Output closed early, e.g. `sshd-lint \| head` (128 + SIGPIPE) |

`64` and `66` follow the conventional values from BSD `sysexits.h`. When using
`--format json`, the verdict is also embedded in the output as `exit_code`, so the report is
fully self-contained.

### GitHub Actions

CI systems treat **any** non-zero exit code as failure, which would collapse the distinction
between `1` and `2`. Translate the verdict explicitly:

```yaml
- name: Install sshd-lint
  run: pip install sshd-lint

- name: Lint SSH config
  run: |
    code=0
    sshd-lint /etc/ssh/sshd_config --format json > report.json || code=$?
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

## Rules Evaluated

### Parse and file handling
- **Rule 00** — Include resolution problems: unreadable files (CRITICAL), a glob matching
  more than 500 files (CRITICAL, refused outright), a glob matching a directory (LOW,
  skipped), a glob matching zero files (INFO), and lines that could not be parsed as a
  directive (LOW).

### Authentication
- **Rule 01** — `PermitRootLogin`
- **Rule 02** — `PasswordAuthentication`
- **Rule 03** — `PermitEmptyPasswords`
- **Rule 04** — `ChallengeResponseAuthentication` / `KbdInteractiveAuthentication`
- **Rule 05** — `PubkeyAuthentication`
- **Rule 06** — `HostbasedAuthentication` / `IgnoreRhosts`

### Access control
- **Rule 10** — `LoginGraceTime`, including `0` (no time limit at all)
- **Rule 11** — `MaxAuthTries`
- **Rule 12** — `MaxSessions`
- **Rule 13** — `MaxStartups`
- **Rule 14** — `AllowUsers` / `AllowGroups`

### Forwarding and tunneling
- **Rule 20** — `X11Forwarding`
- **Rule 21** — `AllowTcpForwarding`
- **Rule 22** — `AllowAgentForwarding`
- **Rule 23** — `GatewayPorts`
- **Rule 24** — `PermitTunnel`

### Logging and auditing
- **Rule 30** — `LogLevel`
- **Rule 31** — `PrintLastLog`

### Cryptography
- **Rule 40** — Weak or deprecated `Ciphers`
- **Rule 41** — Weak or deprecated `MACs`
- **Rule 42** — Weak `KexAlgorithms`
- **Rule 43** — Deprecated `HostKeyAlgorithms`
- **Rule 44** — Deprecated `PubkeyAcceptedAlgorithms` / `PubkeyAcceptedKeyTypes`

Rules 40–44 understand OpenSSH's `+`/`-`/`^` default-set syntax (e.g. `Ciphers +arcfour`
appends to the compiled-in default rather than replacing it) — a weak algorithm is flagged
whether it replaces the list or is merely appended to it.

### Miscellaneous
- **Rule 50** — `Banner`
- **Rule 51** — `StrictModes`
- **Rule 52** — `Port` (every `Port` line, since the directive is cumulative)
- **Rule 53** — `ClientAliveInterval` / `ClientAliveCountMax` idle session timeout
- **Rule 54** — `UseDNS`
- **Rule 55** — Insecure directives inside `Match` blocks (scoped risk)
- **Rule 56** — Duplicate global directives (shadowed by sshd)
- **Rule 57** — `PermitUserEnvironment`

### On the standards references
Each finding cites the baseline it derives from — CIS Benchmark for Linux, Mozilla OpenSSH
Guidelines, NIST SP 800-53, or `sshd_config(5)`. These are attributions of where a
recommendation comes from, not a certified control-by-control mapping. `sshd_lint` is not a
compliance-audit tool and should not be presented as one.

---

## How sshd_lint Differs From Similar Tools

| Tool | How it works | Requires root / live system |
|------|--------------|-----------------------------|
| **Lynis** | Runs live on the system, audits many aspects | Yes |
| **ssh-audit** | Connects to a live SSH server, tests its responses | Yes (network access) |
| **sshd_lint** | Reads the config file statically, offline | No |

`ssh-audit` and `sshd_lint` are complementary rather than competing: one reports what the
server actually negotiates, the other reports what the file says — and whether the file says
what its author believes it says. Only the second works on a configuration you cannot
connect to.

---

## Limitations

- **Static analysis only.** The tool does not connect to a live server or test actual
  behaviour. Always confirm a configuration with `sshd -t` before deploying it.
- **Match block conditions are not evaluated.** The condition string (e.g. `User anoncvs`,
  `Address 10.0.0.0/8`) is recorded and reported, but `sshd_lint` cannot determine whether
  it applies to a given connection.
- **Compiled-in algorithm defaults are not audited.** Rules 40–44 evaluate `Ciphers`,
  `MACs`, `KexAlgorithms`, and related directives only when they are explicitly set. This
  matters: the OpenSSH default `MACs` list still contains `hmac-sha1` and
  `umac-64@openssh.com`, so a configuration that never mentions `MACs` is reported clean
  while still negotiating SHA-1-based and 64-bit-tag MACs. Flagging the vendor default would
  fire on nearly every configuration in existence, so it is out of scope — but it is a blind
  spot, not an endorsement. CIS and Mozilla both recommend setting an explicit algorithm
  list.
- **Include resolution requires filesystem access.** Unreadable files and globs matching
  over 500 files are reported as CRITICAL; a glob matching a directory is skipped and
  reported as LOW; a glob matching zero files is reported as INFO.
- **Relative `Include` paths resolve against `--base-dir` or the config file's own
  directory**, not sshd's hardcoded `/etc/ssh`. For the common case of auditing the live
  `/etc/ssh/sshd_config` these are identical. When auditing a copy of only the main file,
  pass `--base-dir /etc/ssh`.
- **Version-aware rules are currently minimal.** `--openssh-version` adjusts a small number
  of known defaults; more version-specific rules may be added in future releases.
- **Compiled-in defaults target OpenSSH 8.x.** Behaviour on significantly older or newer
  versions may differ.

---

## Repository Layout

```
src/sshd_lint/__init__.py           the analyzer (parser, rules, reporters, CLI)
src/sshd_lint/__main__.py           python -m sshd_lint entry point
samples/                            example configurations (see below)
```

---

## Sample Configurations

The `samples/` directory contains example configurations used both as documentation and as a
lightweight regression suite. Each targets a different aspect of the analyzer.

| File | Purpose | Expected result |
|------|---------|-----------------|
| `hardened.conf` | A known-good baseline with no weaknesses | Zero findings, exit `0` |
| `realistic.conf` | A plausible production config with a realistic spread of issues | Several findings, one HIGH, exit `2` |
| `chaos.conf` | A deliberately catastrophic config that exercises every rule category | Many findings across all severities |
| `tricky.conf` | Subtle mistakes a naive parser skips: time suffixes, aliased directives, cumulative directives, an idle-timeout trap, an uninterpretable value | Findings a simpler linter would miss |
| `edge.conf` + `edge_config.d/` | Include expansion and Match-scope threading across files | Findings correctly scoped to the file and Match condition they come from |

`hardened.conf` in particular acts as a contract: if a future change makes it produce a
finding, either the config or the rule that fired needs a second look.

### On the `edge_config.d/` layout

`edge.conf` includes a directory of drop-in files, exactly as a real `/etc/ssh/sshd_config`
includes `/etc/ssh/sshd_config.d/`. Splitting a single file into a main config plus a
drop-in directory is what lets these samples exercise `Include` expansion at all — without
the directory there would be no include for the tool to follow.

The drop-in files are named with numeric prefixes (`10-cloudinit.conf`, `20-danger.conf`).
This is the standard convention for `*.d` directories across the system — `sysctl.d`,
`NetworkManager/conf.d`, systemd units, cloud-init, and others all use it. sshd reads the
files in lexical order, and because SSH applies the first occurrence of each directive, read
order determines which setting wins. The numeric prefixes make that order explicit and
predictable, and the gaps (10, 20, …) leave room to insert a file between two others later
without renaming anything.

The two drop-ins demonstrate the two scenarios the analyzer is built to get right:

- **`10-cloudinit.conf`** — the everyday case. The main config disables password
  authentication globally, and this drop-in re-enables it for a single automation account
  inside a `Match User` block. The finding must be scoped to that user and attributed to
  this file, not reported as a server-wide regression.
- **`20-danger.conf`** — the footgun. It opens a `Match Address` block and never closes it.
  Because sshd shares Match state across `Include` boundaries, the block remains active when
  control returns to `edge.conf`, so the directives near the end of the *parent* file are
  silently scoped to that address range rather than being global. The analyzer surfaces this
  by scoping those trailing findings to the leaked Match condition.

Run them with:

```bash
sshd-lint samples/tricky.conf --compact
sshd-lint samples/edge.conf --base-dir samples --compact
```

The `--base-dir samples` argument is required for `edge.conf` because its `Include` path is
relative to the `samples/` directory rather than to sshd's hardcoded `/etc/ssh`.

`tricky.conf` is intentionally **not** valid for `sshd -t`: it contains an uninterpretable
value on purpose, to show that `sshd_lint` reports such a value rather than skipping it
silently. Auditing configurations that sshd would itself reject is part of the tool's
purpose.

---

## Author

**capitan0n** — [github.com/capitan0n](https://github.com/capitan0n)

Issues and pull requests are welcome at
[github.com/capitan0n/sshd-lint/issues](https://github.com/capitan0n/sshd-lint/issues).

---

## License

Released under the MIT License. See [LICENSE](LICENSE) for details.
