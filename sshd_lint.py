

# ==============================================================================
# Title:        ssh-lint
# Description:  A lightweight, zero-dependency tool to instantly check SSH status.
# Author:       capitan0n
# Date:         July 2026
# ==============================================================================



#!/usr/bin/env python3
"""
sshd_lint.py — Static analyzer for sshd_config files.

Usage:
    python sshd_lint.py
    python sshd_lint.py /path/to/sshd_config
    python sshd_lint.py sshd_config --severity high
    python sshd_lint.py sshd_config --format json
    python sshd_lint.py sshd_config --openssh-version 8.9
    python sshd_lint.py sshd_config --base-dir /etc/ssh

References used in rules:
    - CIS Benchmark for Linux (SSH section)
    - Mozilla OpenSSH Guidelines (https://infosec.mozilla.org/guidelines/openssh)
    - NIST SP 800-53
    - OpenSSH official documentation
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

__version__ = "1.3.0"

if sys.version_info < (3, 9):
    sys.exit("Error: sshd_lint requires Python 3.9 or newer.")


# ---------------------------------------------------------------------------
# Severity levels
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"

SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]

# ---------------------------------------------------------------------------
# Cumulative directives
#
# In sshd_config, the FIRST occurrence of a directive wins and any later
# occurrence is silently ignored — EXCEPT for the directives listed here,
# which OpenSSH genuinely accepts multiple times and accumulates.
#
# Sources: sshd_config(5), OpenSSH source (servconf.c)
# ---------------------------------------------------------------------------

CUMULATIVE_DIRECTIVES = {
    # AcceptEnv lines accumulate the list of accepted env variables
    "acceptenv",
    # Multiple HostKey paths load different key types (ed25519, rsa, ecdsa…)
    "hostkey",
    # Multiple ListenAddress lines bind to multiple addresses/ports
    "listenaddress",
    # Multiple Port lines listen on multiple ports simultaneously
    "port",
    # One Subsystem line per subsystem name (e.g. sftp, netconf)
    "subsystem",
    # SetEnv accumulates environment variable assignments
    "setenv",
    # Match is a block header, handled separately by the parser
    "match",
    # sshd_config(5): each of these "may appear multiple times ... with
    # each instance appending to the list" -- unlike most directives,
    # they are NOT first-wins. Verify with `sshd -T` if in doubt.
    "allowusers",
    "allowgroups",
    "denyusers",
    "denygroups",
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """One lint finding produced by a rule."""
    severity:    Severity
    directive:   str
    value:       str
    message:     str
    detail:      str
    references:  list[str] = field(default_factory=list)
    line:        Optional[int] = None
    # None  → global scope
    # str   → the Match condition that scopes this finding (e.g. "User anoncvs")
    match_scope: Optional[str] = None


@dataclass
class ParsedDirective:
    """One key-value pair extracted from sshd_config."""
    key:             str
    value:           str
    line:            int
    in_match:        bool = False
    match_condition: str  = ""


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class SshdConfigParser:
    """
    Parses an sshd_config file into a list of ParsedDirective objects.

    Handles:
      - Comments (#) and blank lines
      - Key Value and Key=Value syntax
      - Match blocks (including 'Match All' which resets global context)
      - Include directives with glob expansion
      - Circular Include protection

    Does NOT:
      - Evaluate Match block conditions (only records the condition string)
    """

    DIRECTIVE_RE = re.compile(
        r'^(?P<key>[A-Za-z][A-Za-z0-9]+)\s*[=\s]\s*(?P<value>.+?)\s*$'
    )
    MATCH_RE = re.compile(r'^Match\s+(.+)$', re.IGNORECASE)

    # A single Include line matching more files than this is refused rather
    # than expanded. Guards against a typo'd glob (e.g. an absolute pattern
    # that resolves too close to "/") or a hostile config trying to make an
    # offline audit walk a large chunk of the filesystem.
    MAX_INCLUDE_MATCHES = 500

    def __init__(self, path: Path, base_dir: Path):
        self.path        = path
        self.base_dir    = base_dir
        self.directives: list[ParsedDirective]            = []
        self._visited:   set[Path]                        = set()
        self.parse_errors: list[tuple[Path, str]]         = []
        # Include patterns that matched zero files -- see rule_00_empty_includes.
        self.empty_includes: list[tuple[str, int]]        = []
        # Lines that were not blank/comment/Match/Include and didn't match
        # DIRECTIVE_RE either -- see rule_00_unparsed_lines.
        self.unparsed_lines: list[tuple[Path, int, str]]  = []
        self._by_key: dict[str, list[ParsedDirective]]    = {}

    def parse(self) -> list[ParsedDirective]:
        self._parse_file(self.path)
        for d in self.directives:
            self._by_key.setdefault(d.key.lower(), []).append(d)
        return self.directives

    def _parse_file(self, path: Path):
        if path in self._visited:
            return
        self._visited.add(path)

        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError as exc:
            self.parse_errors.append((path, str(exc)))
            return

        in_match        = False
        match_condition = ""

        for lineno, raw in enumerate(lines, start=1):
            line = raw.strip()

            if not line or line.startswith('#'):
                continue

            # ---- Match block header ----------------------------------------
            m = self.MATCH_RE.match(line)
            if m:
                condition = m.group(1).strip()
                # 'Match All' is a special keyword that ends any Match block
                # and returns to global context (man sshd_config §Match)
                if condition.lower() == "all":
                    in_match        = False
                    match_condition = ""
                else:
                    in_match        = True
                    match_condition = condition
                continue

            # ---- Include directive ------------------------------------------
            if line.lower().startswith('include '):
                # sshd_config(5): "Multiple pathnames may be specified" on a
                # single Include line -- each is its own glob(7) pattern.
                include_args = line.split(None, 1)[1].strip()
                for include_glob in include_args.split():
                    if Path(include_glob).is_absolute():
                        matched_paths = sorted(
                            Path('/').glob(include_glob.lstrip('/'))
                        )
                    else:
                        matched_paths = sorted(self.base_dir.glob(include_glob))

                    if len(matched_paths) > self.MAX_INCLUDE_MATCHES:
                        self.parse_errors.append((
                            Path(include_glob),
                            f"matched {len(matched_paths)} files "
                            f"(> {self.MAX_INCLUDE_MATCHES}); refusing to expand",
                        ))
                        continue

                    if not matched_paths:
                        self.empty_includes.append((include_glob, lineno))

                    for inc_path in matched_paths:
                        # resolve() so the same physical file reached via two
                        # literal paths (e.g. a symlink) is parsed only once.
                        self._parse_file(inc_path.resolve())
                continue

            # ---- Regular directive ------------------------------------------
            m = self.DIRECTIVE_RE.match(line)
            if m:
                self.directives.append(ParsedDirective(
                    key=m.group('key'),
                    value=m.group('value'),
                    line=lineno,
                    in_match=in_match,
                    match_condition=match_condition,
                ))
            else:
                self.unparsed_lines.append((path, lineno, line))

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def get_global(self, key: str) -> Optional[ParsedDirective]:
        """Return the FIRST global (non-Match) directive with the given key.

        This mirrors sshd's own behaviour: when a directive appears multiple
        times in global scope, the first occurrence wins (except for
        CUMULATIVE_DIRECTIVES, which callers handle separately).
        """
        for d in self._by_key.get(key.lower(), ()):
            if not d.in_match:
                return d
        return None

    def get_global_all(self, key: str) -> list[ParsedDirective]:
        """Return ALL global occurrences of a directive (for duplicate detection)."""
        return [d for d in self._by_key.get(key.lower(), ()) if not d.in_match]

    def get_all(self, key: str) -> list[ParsedDirective]:
        """Return all directives (global + Match) with the given key."""
        return list(self._by_key.get(key.lower(), ()))

    def get_shadowed_globals(self) -> list[tuple[ParsedDirective, ParsedDirective]]:
        """Return (winner, shadowed) pairs for duplicate global directives.

        sshd silently ignores every global occurrence of a directive beyond
        the first.  This method finds those shadowed lines so we can warn
        the operator.

        Cumulative directives (see CUMULATIVE_DIRECTIVES) are excluded because
        sshd genuinely uses all of their occurrences.
        """
        seen:     dict[str, ParsedDirective]                         = {}
        shadowed: list[tuple[ParsedDirective, ParsedDirective]]      = []

        for d in self.directives:
            if d.in_match:
                continue
            k = d.key.lower()
            if k in CUMULATIVE_DIRECTIVES:
                continue
            if k in seen:
                shadowed.append((seen[k], d))
            else:
                seen[k] = d

        return shadowed


# ---------------------------------------------------------------------------
# OpenSSH defaults
#
# Compiled-in defaults for OpenSSH 8.x.
# Source: sshd_config(5) man page for OpenSSH 8.9p1.
# ---------------------------------------------------------------------------

OPENSSH_DEFAULTS: dict[str, str] = {
    "permitrootlogin":                 "prohibit-password",
    "passwordauthentication":          "yes",
    "permitemptypasswords":            "no",
    "challengeresponseauthentication": "no",
    "pubkeyauthentication":            "yes",
    "hostbasedauthentication":         "no",
    "ignorerhosts":                    "yes",
    "authorizedkeysfile":              ".ssh/authorized_keys",   # NOTE: correct spelling
    "usepam":                          "no",
    "x11forwarding":                   "no",
    "allowtcpforwarding":              "yes",
    "allowagentforwarding":            "yes",
    "permittunnel":                    "no",
    "gatewayports":                    "no",
    "logingracetime":                  "120",
    "maxauthtries":                    "6",
    "maxsessions":                     "10",
    "maxstartups":                     "10:30:100",
    "banner":                          "none",
    "loglevel":                        "INFO",
    "printlastlog":                    "yes",
    "strictmodes":                     "yes",
    "permituserenvironment":           "no",
    "tcpkeepalive":                    "yes",
    "usedns":                          "no",
    "compression":                     "delayed",
    "clientaliveinterval":             "0",
    "clientalivecountmax":             "3",
    "port":                            "22",
    # The four entries below document OpenSSH's compiled-in algorithm
    # defaults for reference. Rules 40-44 only validate a directive that is
    # explicitly set in the config; an absent directive is assumed to be
    # using these (already secure) compiled-in defaults.
    "ciphers": (
        "chacha20-poly1305@openssh.com,"
        "aes128-ctr,aes192-ctr,aes256-ctr,"
        "aes128-gcm@openssh.com,aes256-gcm@openssh.com"
    ),
    "macs": (
        "umac-64-etm@openssh.com,umac-128-etm@openssh.com,"
        "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,"
        "hmac-sha1-etm@openssh.com,"
        "umac-64@openssh.com,umac-128@openssh.com,"
        "hmac-sha2-256,hmac-sha2-512,hmac-sha1"
    ),
    "kexalgorithms": (
        "curve25519-sha256,curve25519-sha256@libssh.org,"
        "ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
        "diffie-hellman-group-exchange-sha256,"
        "diffie-hellman-group16-sha512,"
        "diffie-hellman-group18-sha512,"
        "diffie-hellman-group14-sha256"
    ),
    "hostkeyalgorithms": (
        "ecdsa-sha2-nistp256-cert-v01@openssh.com,"
        "ecdsa-sha2-nistp384-cert-v01@openssh.com,"
        "ecdsa-sha2-nistp521-cert-v01@openssh.com,"
        "ssh-ed25519-cert-v01@openssh.com,"
        "rsa-sha2-512-cert-v01@openssh.com,"
        "rsa-sha2-256-cert-v01@openssh.com,"
        "ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,"
        "ssh-ed25519,rsa-sha2-512,rsa-sha2-256"
    ),
}

WEAK_CIPHERS = {
    "3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc",
    "arcfour", "arcfour128", "arcfour256",
    "blowfish-cbc", "cast128-cbc", "rijndael-cbc@lysator.liu.se",
}
WEAK_MACS = {
    "hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96",
    "hmac-ripemd160", "umac-32@openssh.com", "umac-64@openssh.com",
}
WEAK_KEX = {
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    "gss-gex-sha1-",
    "gss-group1-sha1-",
    "gss-group14-sha1-",
}
WEAK_HOSTKEY = {"ssh-dss", "ssh-rsa"}

# Ports that offer near-zero obscurity benefit for SSH: they appear in every
# off-the-shelf scanner's SSH port list, so users often pick them thinking
# they've hardened the service when they've only marginally reduced their
# bot-scan volume.
COMMONLY_SCANNED_ALT_PORTS = {2222, 22222, 2022, 22022, 222, 2200}


def _parse_algorithm_directive(value: str) -> tuple[str, set[str]]:
    """Split a Ciphers/MACs/KexAlgorithms/HostKeyAlgorithms/
    PubkeyAcceptedAlgorithms value into (mode, algorithms).

    Since OpenSSH 7.x these directives accept, in addition to a plain
    comma-separated list that replaces the compiled-in default outright:
      "+list"  -- append list to the default set
      "-list"  -- remove list (wildcards allowed) from the default set
      "^list"  -- move list to the front of the default set

    A weak algorithm named in a "+"/"^" list still ends up in the effective
    set and must be checked; one named in a "-" list is being removed, so
    it is not a risk.
    """
    v = value.strip()
    prefix_modes = {"+": "append", "-": "remove", "^": "prepend"}
    if v and v[0] in prefix_modes:
        mode, rest = prefix_modes[v[0]], v[1:]
    else:
        mode, rest = "replace", v
    algorithms = {a.strip().lower() for a in rest.split(',') if a.strip()}
    return mode, algorithms


# ---------------------------------------------------------------------------
# Rule engine
# ---------------------------------------------------------------------------

class RuleEngine:
    """
    Runs all lint rules against a parsed config.

    Each rule is a method named rule_NN_*.  The run() method discovers
    them automatically via dir(), so adding a new rule requires only a
    new method — no registration step needed.
    """

    CIS_REF  = "CIS Benchmark for Linux"
    MOZ_REF  = "Mozilla OpenSSH Guidelines"
    NIST_REF = "NIST SP 800-53 AC-17"
    MAN_REF  = "sshd_config(5)"

    def __init__(self, parser: SshdConfigParser,
                 openssh_version: Optional[str] = None):
        self.parser          = parser
        self.openssh_version = openssh_version
        self.findings:       list[Finding] = []
        self.defaults        = dict(OPENSSH_DEFAULTS)
        self._apply_version_defaults()

    def _apply_version_defaults(self):
        """Adjust baseline defaults for the target OpenSSH version."""
        if not self.openssh_version:
            return
        try:
            m = re.match(r'^(\d+)\.(\d+)', self.openssh_version)
            if m:
                version = float(f"{m.group(1)}.{m.group(2)}")
                # Before 7.0, PermitRootLogin defaulted to 'yes'
                if version < 7.0:
                    self.defaults["permitrootlogin"] = "yes"
        except ValueError:
            pass

    def _get_directive(self, key: str) -> Optional[ParsedDirective]:
        return self.parser.get_global(key)

    def _effective_value(self, key: str) -> str:
        """Return the configured value, or the OpenSSH compiled-in default."""
        d = self._get_directive(key)
        if d:
            return d.value
        return self.defaults.get(key.lower(), "<unknown>")

    def _line(self, key: str) -> Optional[int]:
        d = self._get_directive(key)
        return d.line if d else None

    def _add(self, severity, directive, value, message, detail, refs,
             match_scope=None):
        self.findings.append(Finding(
            severity=severity,
            directive=directive,
            value=value,
            message=message,
            detail=detail,
            references=refs,
            line=self._line(directive),
            match_scope=match_scope,
        ))

    def run(self) -> list[Finding]:
        self.findings = []
        for rule_name in sorted(m for m in dir(self) if m.startswith('rule_')):
            getattr(self, rule_name)()
        return self.findings

    # ------------------------------------------------------------------
    # Rule 00 — Parse errors
    # ------------------------------------------------------------------

    def rule_00_parse_errors(self):
        """Escalate Include-resolution failures to CRITICAL findings.

        Covers a file sshd couldn't read (its directives would be silently
        skipped) and an Include glob that expanded to a suspiciously large
        number of files (typo'd pattern, or a hostile config trying to make
        an offline audit walk a large filesystem tree).
        """
        for path, err in self.parser.parse_errors:
            self._add(
                Severity.CRITICAL,
                "Include", str(path),
                f"Include problem: {err}",
                (
                    "If sshd cannot read an included file, the directives it "
                    "contains are silently ignored -- this can cause critical "
                    "security settings to be bypassed at startup. An oversized "
                    "match is refused outright rather than expanded, since "
                    "that is unlikely to be intentional."
                ),
                ["File System / IO Error", self.MAN_REF],
            )

    def rule_00_empty_includes(self):
        """Flag Include patterns that matched zero files.

        Often benign (e.g. an empty sshd_config.d/ on a fresh install), but
        it can also mean --base-dir doesn't point where you think, or the
        pattern has a typo -- either way, whatever directives were meant to
        live in those files are silently absent from this report.
        """
        for pattern, lineno in self.parser.empty_includes:
            self.findings.append(Finding(
                severity=Severity.INFO,
                directive="Include",
                value=pattern,
                message=f"Include pattern '{pattern}' matched 0 files.",
                detail=(
                    "This may be expected, but if you intended to pull in "
                    "additional configuration here, check --base-dir and the "
                    "pattern itself. Directives in the files you meant to "
                    "include are NOT reflected anywhere else in this report."
                ),
                references=[self.MAN_REF],
                line=lineno,
            ))

    def rule_00_unparsed_lines(self):
        """Flag lines that are neither blank/comment, Match, Include, nor a
        recognisable 'Key Value' directive.

        Usually a typo. A directive that silently fails to parse is a
        directive that silently does not apply.
        """
        for path, lineno, raw in self.parser.unparsed_lines:
            self.findings.append(Finding(
                severity=Severity.LOW,
                directive="(unparsed line)",
                value=raw,
                message=f"Line {lineno} in {path.name} could not be parsed.",
                detail=(
                    "Not a comment, a Match/Include directive, or a "
                    "recognisable 'Key Value' pair, so sshd's behaviour for "
                    "it should not be assumed. Check for a typo or stray "
                    "characters."
                ),
                references=[self.MAN_REF],
                line=lineno,
            ))

    # ------------------------------------------------------------------
    # Rules 01-06 — Authentication
    # ------------------------------------------------------------------

    def rule_01_permit_root_login(self):
        val = self._effective_value("PermitRootLogin").lower()
        if val == "yes":
            self._add(
                Severity.CRITICAL,
                "PermitRootLogin", val,
                "Root login over SSH is permitted.",
                (
                    "Allowing direct root login means a successful brute-force or "
                    "stolen credential grants the attacker immediate root access. "
                    "Use an unprivileged account and escalate with sudo. "
                    "At minimum set 'prohibit-password' to require a key."
                ),
                [self.CIS_REF, self.MOZ_REF, self.NIST_REF],
            )
        elif val in ("without-password", "prohibit-password"):
            self._add(
                Severity.MEDIUM,
                "PermitRootLogin", val,
                "Root login is allowed with a public key (no password required).",
                (
                    "While better than 'yes', direct root key-based login still "
                    "skips least-privilege and audit trails. Prefer 'no' and "
                    "use a regular user with sudo for privileged operations."
                ),
                [self.CIS_REF, self.MOZ_REF],
            )

    def rule_02_password_authentication(self):
        val = self._effective_value("PasswordAuthentication").lower()
        if val == "yes":
            self._add(
                Severity.HIGH,
                "PasswordAuthentication", val,
                "Password authentication is enabled.",
                (
                    "Password authentication is vulnerable to brute-force and "
                    "credential-stuffing attacks. Disable it and use public-key "
                    "authentication exclusively: 'PasswordAuthentication no'."
                ),
                [self.CIS_REF, self.MOZ_REF],
            )

    def rule_03_permit_empty_passwords(self):
        val = self._effective_value("PermitEmptyPasswords").lower()
        if val == "yes":
            self._add(
                Severity.CRITICAL,
                "PermitEmptyPasswords", val,
                "Accounts with empty passwords can authenticate via SSH.",
                (
                    "Any local account without a password becomes trivially "
                    "accessible over the network. This must always be 'no'."
                ),
                [self.CIS_REF, self.MOZ_REF],
            )

    def rule_04_challenge_response(self):
        val = self._effective_value("ChallengeResponseAuthentication").lower()
        if val == "yes":
            self._add(
                Severity.MEDIUM,
                "ChallengeResponseAuthentication", val,
                "Challenge-response authentication is enabled.",
                (
                    "Unless you specifically need TOTP or PAM challenge-response, "
                    "disable this. When combined with PAM it can inadvertently "
                    "allow password-based logins even when PasswordAuthentication "
                    "is 'no'."
                ),
                [self.CIS_REF, self.MAN_REF],
            )

    def rule_05_pubkey_authentication(self):
        val = self._effective_value("PubkeyAuthentication").lower()
        if val == "no":
            self._add(
                Severity.HIGH,
                "PubkeyAuthentication", val,
                "Public key authentication is disabled.",
                (
                    "Public key auth is the recommended secure method. "
                    "Disabling it forces users to fall back to weaker methods "
                    "such as password authentication."
                ),
                [self.MOZ_REF, self.NIST_REF],
            )

    def rule_06_hostbased_authentication(self):
        val = self._effective_value("HostbasedAuthentication").lower()
        if val == "yes":
            self._add(
                Severity.HIGH,
                "HostbasedAuthentication", val,
                "Host-based authentication is enabled.",
                (
                    "Trusts a client based on its IP/hostname and a host key "
                    "rather than verifying the actual user, which makes it "
                    "vulnerable to IP spoofing and DNS manipulation. "
                    "Considered legacy; disable unless you have a specific, "
                    "well-understood need: 'HostbasedAuthentication no'."
                ),
                [self.CIS_REF, self.MOZ_REF],
            )

        ignore_rhosts = self._effective_value("IgnoreRhosts").lower()
        if val == "yes" and ignore_rhosts == "no":
            self._add(
                Severity.HIGH,
                "IgnoreRhosts", ignore_rhosts,
                "Host-based auth honours per-user ~/.rhosts and ~/.shosts files.",
                (
                    "With IgnoreRhosts no, any user can grant host-based "
                    "trust to another host simply by writing their own "
                    "~/.rhosts file, entirely outside admin control. Set "
                    "'IgnoreRhosts yes' (the compiled-in default) unless you "
                    "specifically rely on per-user rhosts files."
                ),
                [self.CIS_REF, self.MAN_REF],
            )

    # ------------------------------------------------------------------
    # Rules 10-14 — Access control
    # ------------------------------------------------------------------

    def rule_10_login_grace_time(self):
        raw = self._effective_value("LoginGraceTime")
        try:
            seconds = int(raw)
        except ValueError:
            return
        if seconds > 60:
            self._add(
                Severity.LOW,
                "LoginGraceTime", raw,
                f"LoginGraceTime is {seconds}s — recommended ≤ 60s.",
                (
                    "A long grace time keeps unauthenticated connections alive "
                    "longer, making resource-exhaustion DoS attacks easier. "
                    "Set to 30 or 60 seconds."
                ),
                [self.CIS_REF],
            )

    def rule_11_max_auth_tries(self):
        raw = self._effective_value("MaxAuthTries")
        try:
            n = int(raw)
        except ValueError:
            return
        if n > 4:
            self._add(
                Severity.MEDIUM,
                "MaxAuthTries", raw,
                f"MaxAuthTries is {n} — recommended ≤ 4.",
                (
                    "A higher value gives an attacker more credential attempts "
                    "per TCP connection before being disconnected, easing "
                    "brute-force. Set to 3 or 4."
                ),
                [self.CIS_REF],
            )

    def rule_12_max_sessions(self):
        raw = self._effective_value("MaxSessions")
        try:
            n = int(raw)
        except ValueError:
            return
        if n > 10:
            self._add(
                Severity.LOW,
                "MaxSessions", raw,
                f"MaxSessions is {n} — consider limiting to ≤ 10.",
                (
                    "An excessively high session count per connection can be "
                    "abused for resource exhaustion. The default of 10 is "
                    "reasonable for most servers."
                ),
                [self.MAN_REF],
            )

    def rule_13_max_startups(self):
        raw   = self._effective_value("MaxStartups")
        parts = raw.split(':')
        try:
            full = int(parts[-1])
        except (ValueError, IndexError):
            return
        if full > 100:
            self._add(
                Severity.LOW,
                "MaxStartups", raw,
                "MaxStartups 'full' threshold is very high — consider reducing.",
                (
                    "MaxStartups limits the number of concurrent unauthenticated "
                    "connections. A very high 'full' value reduces protection "
                    "against connection-flooding DoS. Recommended: '10:30:60'."
                ),
                [self.MAN_REF, self.CIS_REF],
            )

    def rule_14_allow_users_or_groups(self):
        has_allow = (
            self._get_directive("AllowUsers")  is not None or
            self._get_directive("AllowGroups") is not None
        )
        if not has_allow:
            self._add(
                Severity.MEDIUM,
                "AllowUsers / AllowGroups", "<not set>",
                "No user or group allowlist is defined.",
                (
                    "Without AllowUsers or AllowGroups, any local user with "
                    "valid credentials can authenticate via SSH. Explicitly "
                    "whitelisting permitted users reduces the attack surface. "
                    "Example: 'AllowGroups sshusers'."
                ),
                [self.CIS_REF, self.MOZ_REF],
            )

    # ------------------------------------------------------------------
    # Rules 20-24 — Forwarding & tunneling
    # ------------------------------------------------------------------

    def rule_20_x11_forwarding(self):
        val = self._effective_value("X11Forwarding").lower()
        if val == "yes":
            self._add(
                Severity.MEDIUM,
                "X11Forwarding", val,
                "X11 forwarding is enabled.",
                (
                    "X11 forwarding can be exploited to hijack the user's X "
                    "display (keylogging, screen capture). Disable unless "
                    "explicitly required: 'X11Forwarding no'."
                ),
                [self.CIS_REF, self.MOZ_REF],
            )

    def rule_21_tcp_forwarding(self):
        val = self._effective_value("AllowTcpForwarding").lower()
        if val == "yes":
            self._add(
                Severity.LOW,
                "AllowTcpForwarding", val,
                "TCP port forwarding is allowed.",
                (
                    "TCP forwarding lets users tunnel arbitrary traffic through "
                    "the SSH connection, potentially bypassing firewall rules. "
                    "Set 'AllowTcpForwarding no' unless you intentionally use "
                    "SSH tunnels (e.g. jump hosts, SOCKS proxying)."
                ),
                [self.CIS_REF, self.MOZ_REF],
            )

    def rule_22_agent_forwarding(self):
        val = self._effective_value("AllowAgentForwarding").lower()
        if val == "yes":
            self._add(
                Severity.LOW,
                "AllowAgentForwarding", val,
                "SSH agent forwarding is allowed.",
                (
                    "Agent forwarding exposes your local SSH key agent to the "
                    "remote server. A compromised server or its root user could "
                    "use the forwarded agent to authenticate to other hosts. "
                    "Use 'ProxyJump' instead of agent forwarding for jump hosts."
                ),
                [self.MOZ_REF, self.MAN_REF],
            )

    def rule_23_gateway_ports(self):
        val = self._effective_value("GatewayPorts").lower()
        if val == "yes":
            self._add(
                Severity.MEDIUM,
                "GatewayPorts", val,
                "GatewayPorts is enabled — remote-forwarded ports bind to all interfaces.",
                (
                    "With GatewayPorts yes, SSH -R tunnels listen on all network "
                    "interfaces instead of just localhost. This can unintentionally "
                    "expose internal services to external networks."
                ),
                [self.MAN_REF],
            )

    def rule_24_permit_tunnel(self):
        val = self._effective_value("PermitTunnel").lower()
        if val not in ("no", "<unknown>"):
            self._add(
                Severity.MEDIUM,
                "PermitTunnel", val,
                "Layer-3 tun device tunneling is permitted.",
                (
                    "PermitTunnel allows VPN-like tun device tunnels through SSH. "
                    "Unless you specifically run an SSH-based VPN, set this to 'no'."
                ),
                [self.MAN_REF, self.MOZ_REF],
            )

    # ------------------------------------------------------------------
    # Rules 30-31 — Logging
    # ------------------------------------------------------------------

    def rule_30_log_level(self):
        val = self._effective_value("LogLevel").upper()
        if val in ("QUIET", "FATAL", "ERROR"):
            self._add(
                Severity.MEDIUM,
                "LogLevel", val,
                f"LogLevel '{val}' suppresses important security events.",
                (
                    "Suppressed log levels hide authentication failures, "
                    "connection events, and key fingerprints — all of which "
                    "are essential for incident detection and forensics. "
                    "Use INFO or VERBOSE."
                ),
                [self.CIS_REF],
            )

    def rule_31_print_last_log(self):
        val = self._effective_value("PrintLastLog").lower()
        if val == "no":
            self._add(
                Severity.LOW,
                "PrintLastLog", val,
                "Last login information is not shown to users at login.",
                (
                    "Displaying the last login time and source IP lets users "
                    "notice unexpected logins. Set 'PrintLastLog yes'."
                ),
                [self.CIS_REF],
            )

    # ------------------------------------------------------------------
    # Rules 40-43 — Cryptography
    # ------------------------------------------------------------------

    def rule_40_weak_ciphers(self):
        d = self._get_directive("Ciphers")
        if d is None:
            return   # Using safe compiled-in defaults — skip
        mode, configured = _parse_algorithm_directive(d.value)
        if mode == "remove":
            return   # "-list" removes entries from the default set — not a risk
        found_weak = configured & WEAK_CIPHERS
        if found_weak:
            self._add(
                Severity.HIGH,
                "Ciphers", d.value,
                f"Weak/deprecated cipher(s) configured: {', '.join(sorted(found_weak))}.",
                (
                    "CBC-mode ciphers (BEAST, Lucky13) and RC4 (statistical "
                    "biases) are cryptographically broken. Use only CTR or "
                    "AEAD modes: chacha20-poly1305, aes*-gcm, aes*-ctr."
                ),
                [self.MOZ_REF, self.CIS_REF],
            )

    def rule_41_weak_macs(self):
        d = self._get_directive("MACs")
        if d is None:
            return
        mode, configured = _parse_algorithm_directive(d.value)
        if mode == "remove":
            return
        found_weak = configured & WEAK_MACS
        if found_weak:
            self._add(
                Severity.HIGH,
                "MACs", d.value,
                f"Weak/deprecated MAC(s) configured: {', '.join(sorted(found_weak))}.",
                (
                    "MD5 and plain SHA1-based MACs are cryptographically weak. "
                    "Prefer ETM (Encrypt-then-MAC) variants: "
                    "hmac-sha2-256-etm, hmac-sha2-512-etm, umac-128-etm."
                ),
                [self.MOZ_REF, self.CIS_REF],
            )

    def rule_42_weak_kex(self):
        d = self._get_directive("KexAlgorithms")
        if d is None:
            return
        mode, configured = _parse_algorithm_directive(d.value)
        if mode == "remove":
            return
        found_weak = {
            k for k in configured
            if any(k.startswith(w) for w in WEAK_KEX)
        }
        if found_weak:
            self._add(
                Severity.HIGH,
                "KexAlgorithms", d.value,
                f"Weak key-exchange algorithm(s): {', '.join(sorted(found_weak))}.",
                (
                    "DH group1 (768-bit) and group14 with SHA1 are too weak by "
                    "modern standards and vulnerable to Logjam. Use "
                    "curve25519 or group16/18 with SHA512."
                ),
                [self.MOZ_REF, self.CIS_REF],
            )

    def rule_43_weak_host_key_algos(self):
        d = self._get_directive("HostKeyAlgorithms")
        if d is None:
            return
        mode, configured = _parse_algorithm_directive(d.value)
        if mode == "remove":
            return
        found_weak = configured & WEAK_HOSTKEY
        if found_weak:
            self._add(
                Severity.HIGH,
                "HostKeyAlgorithms", d.value,
                f"Deprecated host key algorithm(s): {', '.join(sorted(found_weak))}.",
                (
                    "DSA (ssh-dss) is 1024-bit and broken. "
                    "ssh-rsa with SHA1 is deprecated since OpenSSH 8.8. "
                    "Use ssh-ed25519 or rsa-sha2-512 / rsa-sha2-256."
                ),
                [self.MOZ_REF, "OpenSSH Release Notes (8.8)"],
            )

    def rule_44_weak_pubkey_accepted_algorithms(self):
        # Called PubkeyAcceptedKeyTypes before OpenSSH 8.5; only the
        # current name is checked here.
        d = self._get_directive("PubkeyAcceptedAlgorithms")
        if d is None:
            return
        mode, configured = _parse_algorithm_directive(d.value)
        if mode == "remove":
            return
        found_weak = configured & WEAK_HOSTKEY
        if found_weak:
            self._add(
                Severity.HIGH,
                "PubkeyAcceptedAlgorithms", d.value,
                f"Deprecated public-key signature algorithm(s): {', '.join(sorted(found_weak))}.",
                (
                    "Governs which client key algorithms sshd accepts for "
                    "user authentication. ssh-rsa (SHA-1 based) has been "
                    "deprecated since OpenSSH 8.8, and ssh-dss (1024-bit "
                    "DSA) is broken. Use ssh-ed25519 or rsa-sha2-512/256."
                ),
                [self.MOZ_REF, "OpenSSH Release Notes (8.8)"],
            )

    # ------------------------------------------------------------------
    # Rules 50-54 — Miscellaneous
    # ------------------------------------------------------------------

    def rule_50_banner(self):
        val = self._effective_value("Banner").lower()
        if val in ("none", "<unknown>"):
            self._add(
                Severity.INFO,
                "Banner", val,
                "No login banner is configured.",
                (
                    "A pre-login banner can serve as a legal notice that "
                    "unauthorized access is prohibited, which may be required "
                    "by organizational policy or law. "
                    "Example: 'Banner /etc/issue.net'."
                ),
                [self.CIS_REF, self.NIST_REF],
            )

    def rule_51_strict_modes(self):
        val = self._effective_value("StrictModes").lower()
        if val == "no":
            self._add(
                Severity.MEDIUM,
                "StrictModes", val,
                "StrictModes is disabled — sshd will not check file permissions.",
                (
                    "StrictModes yes causes sshd to verify that ~/.ssh and "
                    "authorized_keys have safe ownership and permissions. "
                    "Disabling it allows insecure permissions to go undetected, "
                    "potentially permitting unauthorized key injection."
                ),
                [self.CIS_REF, self.MAN_REF],
            )

    def rule_52_port(self):
        raw = self._effective_value("Port")
        try:
            port = int(raw)
        except ValueError:
            return

        if port == 22:
            self._add(
                Severity.INFO,
                "Port", raw,
                "SSH is listening on the default port 22.",
                (
                    "The default port receives constant automated scan traffic "
                    "which floods auth logs and can hide targeted attacks in "
                    "the noise. Moving to a non-default port is log hygiene, "
                    "not a security control -- strong authentication is what "
                    "actually matters. If you do change it, avoid predictable "
                    "alternates like 2222 or 2022 and pick a less obvious "
                    "high-numbered port instead."
                ),
                ["Security best practice (low priority)"],
            )
        elif port in COMMONLY_SCANNED_ALT_PORTS:
            self._add(
                Severity.INFO,
                "Port", raw,
                f"SSH is listening on port {port}, a commonly-scanned SSH alternate.",
                (
                    "Non-default ports like 2222, 22222, 2022, 22022, 222 and "
                    "2200 are hard-coded into most bot scanner port lists, so "
                    "they offer very little obscurity benefit over port 22. "
                    "If you moved off 22 specifically to reduce scan noise, "
                    "pick a less predictable high-numbered port (e.g. somewhere "
                    "above 10000 that isn't a well-known service port). "
                    "Regardless, port choice is not a substitute for strong "
                    "authentication."
                ),
                ["Security best practice (informational)"],
            )

    def rule_53_client_alive(self):
        interval = self._effective_value("ClientAliveInterval")
        try:
            i = int(interval)
        except ValueError:
            return
        if i == 0:
            self._add(
                Severity.LOW,
                "ClientAliveInterval", interval,
                "No idle session timeout is configured.",
                (
                    "Without a ClientAliveInterval, idle authenticated sessions "
                    "remain open indefinitely — an opportunity for an attacker "
                    "on an unattended terminal. Set 'ClientAliveInterval 300' "
                    "and 'ClientAliveCountMax 2' to disconnect after ~10 min."
                ),
                [self.CIS_REF],
            )

    def rule_54_use_dns(self):
        val = self._effective_value("UseDNS").lower()
        if val == "yes":
            self._add(
                Severity.INFO,
                "UseDNS", val,
                "UseDNS is enabled — sshd performs reverse DNS lookups on connect.",
                (
                    "Reverse DNS lookups add latency to every connection and "
                    "can fail silently in environments with poor DNS resolution. "
                    "They provide minimal security value. Set 'UseDNS no'."
                ),
                [self.MAN_REF],
            )

    # ------------------------------------------------------------------
    # Rule 55 — Match block overrides
    # ------------------------------------------------------------------

    def rule_55_match_block_overrides(self):
        """Check Match blocks for insecure directive overrides.

        A Match block can re-enable a dangerous setting for a subset of
        connections even when the global config is secure.  Each finding
        is tagged with the match_scope so the operator knows the risk is
        scoped — not server-wide.
        """
        # directive → (insecure values, severity, short reason)
        MATCH_CHECKS: dict[str, tuple[set, Severity, str]] = {
            "PermitRootLogin": (
                {"yes"},
                Severity.HIGH,
                "allows root login for matched connections",
            ),
            "PasswordAuthentication": (
                {"yes"},
                Severity.HIGH,
                "allows password login for matched connections, "
                "bypassing the global 'no'",
            ),
            "PermitEmptyPasswords": (
                {"yes"},
                Severity.CRITICAL,
                "permits empty-password accounts for matched connections",
            ),
            "X11Forwarding": (
                {"yes"},
                Severity.MEDIUM,
                "enables X11 forwarding for matched connections",
            ),
            "AllowTcpForwarding": (
                {"yes", "local", "remote"},
                Severity.LOW,
                "enables TCP forwarding for matched connections",
            ),
            "GatewayPorts": (
                {"yes", "clientspecified"},
                Severity.MEDIUM,
                "exposes forwarded ports on all interfaces for matched connections",
            ),
        }

        for key, (bad_values, sev, reason) in MATCH_CHECKS.items():
            for d in self.parser.get_all(key):
                if not d.in_match:
                    continue
                if d.value.lower() in bad_values:
                    self.findings.append(Finding(
                        severity=sev,
                        directive=key,
                        value=d.value,
                        message=(
                            f"Match block [{d.match_condition}] sets "
                            f"{key} {d.value} — {reason}."
                        ),
                        detail=(
                            f"The global setting may be secure, but this Match block "
                            f"overrides it for connections matching: "
                            f"'{d.match_condition}'. "
                            f"This is a scoped risk — not a server-wide issue — "
                            f"but it can still be exploited by an attacker who "
                            f"meets the match condition."
                        ),
                        references=[self.CIS_REF, self.MAN_REF],
                        line=d.line,
                        match_scope=d.match_condition,
                    ))

    # ------------------------------------------------------------------
    # Rule 56 — Duplicate directives
    # ------------------------------------------------------------------

    def rule_56_duplicate_directives(self):
        """Warn about shadowed global directives.

        sshd silently ignores every global occurrence of a directive beyond
        the first.  Operators who add a 'corrected' value at the bottom of
        the file without removing the original will end up with the wrong
        value active — a dangerous false sense of security.
        """
        for winner, shadowed in self.parser.get_shadowed_globals():
            self.findings.append(Finding(
                severity=Severity.MEDIUM,
                directive=shadowed.key,
                value=shadowed.value,
                message=(
                    f"Duplicate directive — '{shadowed.key} {shadowed.value}' "
                    f"(line {shadowed.line}) is IGNORED by sshd."
                ),
                detail=(
                    f"sshd uses the FIRST occurrence of each directive. "
                    f"The effective value is '{winner.value}' "
                    f"from line {winner.line}. "
                    f"The duplicate on line {shadowed.line} "
                    f"('{shadowed.value}') is silently discarded. "
                    f"Remove the duplicate or the original to make the "
                    f"intent unambiguous."
                ),
                references=[self.MAN_REF],
                line=shadowed.line,
                match_scope=None,
            ))

    # ------------------------------------------------------------------
    # Rule 57 — Session / environment hardening
    # ------------------------------------------------------------------

    def rule_57_permit_user_environment(self):
        val = self._effective_value("PermitUserEnvironment").lower()
        if val == "yes":
            self._add(
                Severity.MEDIUM,
                "PermitUserEnvironment", val,
                "Users can set environment variables via ~/.ssh/environment.",
                (
                    "Lets any user influence their own session's environment "
                    "without administrator involvement. Combined with "
                    "LD_PRELOAD-sensitive setups or loosely sandboxed "
                    "services, this widens the attack surface. Default and "
                    "recommended: 'PermitUserEnvironment no'."
                ),
                [self.CIS_REF, self.MAN_REF],
            )


# ---------------------------------------------------------------------------
# Reporter
# ---------------------------------------------------------------------------

SEVERITY_COLOR = {
    Severity.CRITICAL: "\033[1;31m",   # bold red
    Severity.HIGH:     "\033[0;31m",   # red
    Severity.MEDIUM:   "\033[0;33m",   # yellow
    Severity.LOW:      "\033[0;34m",   # blue
    Severity.INFO:     "\033[0;37m",   # grey
}
RESET = "\033[0m"


def _colorize(text: str, severity: Severity, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{SEVERITY_COLOR[severity]}{text}{RESET}"


def report_text(findings: list[Finding],
                use_color: bool = True,
                compact:   bool = False) -> str:
    if not findings:
        return "✓ No issues found.\n"

    lines = []
    for f in findings:
        sev = _colorize(f"[{f.severity.value}]", f.severity, use_color)
        loc = f" (line {f.line})" if f.line else ""
        scope_tag = (
            _colorize(f" [Match: {f.match_scope}]", Severity.INFO, use_color)
            if f.match_scope else ""
        )

        lines.append(f"{sev} {f.directive}{loc}{scope_tag}")
        lines.append(f"  Current value : {f.value}")
        lines.append(f"  Issue         : {f.message}")
        if not compact:
            lines.append(f"  Why it matters: {f.detail}")
            if f.references:
                lines.append(f"  References    : {' | '.join(f.references)}")
        lines.append("")

    return "\n".join(lines)


def report_json(findings: list[Finding], exit_code: int) -> str:
    """Produce a self-contained JSON report.

    The top-level object includes:
      exit_code — same value the process will exit with (0/1/2), so
                  consumers don't need to capture $? separately.
      summary   — per-severity counts for quick dashboard integration.
      findings  — the full list of findings.
    """
    return json.dumps(
        {
            "exit_code": exit_code,
            "summary": {
                s.value: sum(1 for f in findings if f.severity == s)
                for s in SEVERITY_ORDER
            },
            "findings": [
                {
                    "severity":   f.severity.value,
                    "directive":  f.directive,
                    "value":      f.value,
                    "line":       f.line,
                    "scope":      f.match_scope if f.match_scope else "global",
                    "message":    f.message,
                    "detail":     f.detail,
                    "references": f.references,
                }
                for f in findings
            ],
        },
        indent=2,
        ensure_ascii=False,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="Static linter / security analyzer for sshd_config files.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--version", "-v",
        action="version",
        version=f"sshd_lint {__version__}",
    )
    p.add_argument(
        "config",
        type=Path,
        nargs="?",
        default=Path("/etc/ssh/sshd_config"),
        help="Path to sshd_config (default: /etc/ssh/sshd_config).",
    )
    p.add_argument(
        "--severity", "-s",
        choices=["critical", "high", "medium", "low", "info"],
        default="info",
        help="Minimum severity to report (default: info = all).",
    )
    p.add_argument(
        "--format", "-f",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text).",
    )
    p.add_argument(
        "--compact", "-c",
        action="store_true",
        help="Hide 'Why it matters' and 'References' for cleaner output.",
    )
    p.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color output.",
    )
    p.add_argument(
        "--openssh-version",
        metavar="VERSION",
        default=None,
        help="OpenSSH version of the target (e.g. 8.9) for version-aware rules.",
    )
    p.add_argument(
        "--base-dir",
        type=Path,
        default=None,
        help=(
            "Base directory for resolving relative Include paths. "
            "Default: the directory containing the config file. "
            "Override with /etc/ssh when auditing a copy of a live system config."
        ),
    )
    return p.parse_args()


def severity_gte(sev: Severity, minimum: Severity) -> bool:
    return SEVERITY_ORDER.index(sev) <= SEVERITY_ORDER.index(minimum)


def main():
    args = parse_args()

    config_path = args.config.expanduser().resolve()
    if not config_path.exists():
        print(f"Error: file not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    # Resolve base_dir: explicit flag > directory of the config file.
    # Using the config file's own directory as default means Include paths
    # are resolved relative to wherever the config lives — which is correct
    # both for /etc/ssh/sshd_config and for offline copies under /tmp/audit/.
    base_dir = (
        args.base_dir.expanduser().resolve()
        if args.base_dir
        else config_path.parent
    )

    # Parse
    parser = SshdConfigParser(config_path, base_dir)
    parser.parse()

    # Run rules
    engine      = RuleEngine(parser, args.openssh_version)
    all_findings = engine.run()

    # Filter by minimum severity
    min_sev  = Severity(args.severity.upper())
    findings = [f for f in all_findings if severity_gte(f.severity, min_sev)]

    # Sort: CRITICAL first, INFO last
    findings.sort(key=lambda f: SEVERITY_ORDER.index(f.severity))

    # Compute exit code first — needed by both the JSON reporter and sys.exit().
    #   0  — no findings at or above the requested severity threshold
    #   1  — findings exist, but none are HIGH or CRITICAL
    #   2  — at least one HIGH or CRITICAL finding (pipeline should fail)
    if any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings):
        exit_code = 2
    elif findings:
        exit_code = 1
    else:
        exit_code = 0

    use_color = not args.no_color and sys.stdout.isatty()

    if args.format == "text":
        by_sev = {s: sum(1 for f in findings if f.severity == s) for s in Severity}
        print(f"\nsshd_lint {__version__} — {config_path}")
        print(f"{'─' * 60}")
        print(
            f"Findings: {len(findings)}  "
            + "  ".join(
                _colorize(f"{s.value}: {by_sev[s]}", s, use_color)
                for s in SEVERITY_ORDER
                if by_sev[s] > 0
            )
        )
        print(f"{'─' * 60}\n")
        print(report_text(findings, use_color=use_color, compact=args.compact))
    else:
        # Pass exit_code into the JSON report so it is self-contained:
        # consumers can read exit_code from the JSON instead of capturing $?.
        print(report_json(findings, exit_code))

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
