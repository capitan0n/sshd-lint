#!/usr/bin/env python3
"""
fuzz_diff.py -- structure-aware and differential fuzzer for sshd-lint.

Zero dependencies, stdlib only. Runs the linter as a subprocess, so it makes
no assumptions about internal APIs.

Three oracle families:

  INVARIANTS   Properties that must hold for ANY input:
               - exit code is always in the documented set
               - no Python traceback ever reaches stderr
               - --json always emits parseable JSON with a stable shape
               - identical input produces byte-identical output (determinism)
               - each run completes inside a wall-clock budget

  DIFFERENTIAL Compares the linter against the real `sshd` binary:
               - D1 validity agreement: if `sshd -t` accepts a config, the
                 linter must not fail with an operational/parse error
               - D2 vocabulary agreement: if `sshd -T` knows a directive,
                 rule 58 (unknown directive) must not fire on it
               Skipped automatically when `sshd` is unavailable.

  ADAPTER      Optional value-level diff against `sshd -T`. Requires wiring
               one function to the linter's internal parser -- see
               parse_config_adapter() near the bottom of this file.

Usage:
    python3 tests/fuzz_diff.py                       # 2000 iterations, seed 0
    python3 tests/fuzz_diff.py -n 50000 --seed 7
    python3 tests/fuzz_diff.py --corpus tests/fixtures --keep-going
    python3 tests/fuzz_diff.py --no-sshd             # invariants only
    python3 tests/fuzz_diff.py --quick               # 300 iterations, for CI

Failures are written to tests/fuzz-crashes/<id>/ with a repro.sh.
"""

from __future__ import annotations

import argparse
import glob as globmod
import hashlib
import json
import os
import random
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

# How to invoke the linter. Overridable with --target.
DEFAULT_TARGET = "python3 -m sshd_lint"

# Security verdict codes plus operational/CLI error codes. Anything else is a
# bug: an uncaught exception surfacing as 1 is indistinguishable from
# "findings present", so we also check stderr for tracebacks.
ALLOWED_EXIT_CODES = {0, 1, 2, 64, 66}

# Exit codes that mean "the linter refused to analyse this file".
OPERATIONAL_ERROR_CODES = {64, 66}

# Rule numbers this fuzzer reasons about. Adjust if the numbering changes.
RULE_UNKNOWN_DIRECTIVE = 58

# Per-run wall clock budget in seconds.
DEFAULT_TIMEOUT = 10.0

# Directives sshd accepts but does not print in `sshd -T` output. Without this
# allowlist D2 would report false positives against the linter.
SSHD_T_OMITTED = {
    "match", "include", "hostkey", "hostcertificate", "hostkeyagent",
    "trustedusercakeys", "revokedkeys", "authorizedkeyscommand",
    "authorizedkeyscommanduser", "authorizedprincipalscommand",
    "authorizedprincipalscommanduser", "chrootdirectory", "forcecommand",
    "banner", "acceptenv", "setenv", "subsystem", "permitlisten",
    "permitopen", "denyusers", "allowusers", "denygroups", "allowgroups",
    "listenaddress", "port", "protocol", "useprivilegeseparation",
    "keyregenerationinterval", "rhostsrsaauthentication", "rsaauthentication",
    "serverkeybits", "uselogin", "challengeresponseauthentication",
}

# Real directive names, used both by the generator and as typo seeds.
DIRECTIVES = [
    "AcceptEnv", "AddressFamily", "AllowAgentForwarding", "AllowGroups",
    "AllowStreamLocalForwarding", "AllowTcpForwarding", "AllowUsers",
    "AuthenticationMethods", "AuthorizedKeysCommand", "AuthorizedKeysFile",
    "AuthorizedPrincipalsFile", "Banner", "CASignatureAlgorithms",
    "ChallengeResponseAuthentication", "ChrootDirectory", "Ciphers",
    "ClientAliveCountMax", "ClientAliveInterval", "Compression",
    "DenyGroups", "DenyUsers", "DisableForwarding", "ExposeAuthInfo",
    "FingerprintHash", "ForceCommand", "GatewayPorts", "GSSAPIAuthentication",
    "GSSAPICleanupCredentials", "HostbasedAuthentication", "HostKey",
    "HostKeyAlgorithms", "IgnoreRhosts", "IgnoreUserKnownHosts", "Include",
    "IPQoS", "KbdInteractiveAuthentication", "KerberosAuthentication",
    "KexAlgorithms", "ListenAddress", "LoginGraceTime", "LogLevel",
    "MACs", "MaxAuthTries", "MaxSessions", "MaxStartups", "PasswordAuthentication",
    "PermitEmptyPasswords", "PermitListen", "PermitOpen", "PermitRootLogin",
    "PermitTTY", "PermitTunnel", "PermitUserEnvironment", "PermitUserRC",
    "PidFile", "Port", "PrintLastLog", "PrintMotd", "PubkeyAcceptedAlgorithms",
    "PubkeyAuthentication", "RekeyLimit", "RevokedKeys", "SetEnv",
    "StreamLocalBindMask", "StreamLocalBindUnlink", "StrictModes",
    "Subsystem", "SyslogFacility", "TCPKeepAlive", "TrustedUserCAKeys",
    "UseDNS", "UsePAM", "UserKnownHostsFile", "VersionAddendum",
    "X11DisplayOffset", "X11Forwarding", "X11UseLocalhost", "XAuthLocation",
]

BOOL_VALUES = [
    "yes", "no", "YES", "No", "Yes", "nO", "true", "false", "1", "0", "",
    "yes ", " no", "yes#comment", "y e s", "yes\tno", "prohibit-password",
]

SEPARATORS = [" ", "\t", "=", " = ", "\t=\t", "  ", " \t ", "=  ", "   =   "]

TRICKY_VALUES = [
    "2h30m", "9999999999999999999999999999999", "-1", "0", "0x10", "1e10",
    "+5", "  ", '"quoted value"', '"unbalanced', "value with spaces",
    "a,b,c", "+aes256-gcm@openssh.com", "-*", "^ssh-ed25519", "*",
    "/etc/ssh/sshd_config.d/*.conf", "~/relative", "../../../etc/passwd",
    "%h/%u", "\x01\x02control", "ünïcödé", "a" * 4096, "0" * 300,
]


# --------------------------------------------------------------------------
# Test case model
# --------------------------------------------------------------------------

class Case:
    """One fuzz input: a main config plus optional included files."""

    def __init__(self, main: bytes, includes: dict[str, bytes] | None = None,
                 origin: str = "generated"):
        self.main = main
        self.includes = includes or {}
        self.origin = origin

    def digest(self) -> str:
        h = hashlib.sha256()
        h.update(self.main)
        for name in sorted(self.includes):
            h.update(name.encode())
            h.update(self.includes[name])
        return h.hexdigest()[:16]

    def materialise(self, root: str) -> str:
        """Write the case to disk under root, return the main config path."""
        main_path = os.path.join(root, "sshd_config")
        with open(main_path, "wb") as fh:
            fh.write(self.main)
        for rel, data in self.includes.items():
            dest = os.path.join(root, rel)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "wb") as fh:
                fh.write(data)
        return main_path

    def text(self) -> str:
        return self.main.decode("utf-8", errors="replace")

    def line(self, n: int) -> str:
        """1-indexed line lookup, tolerant of out-of-range."""
        lines = self.text().splitlines()
        if 1 <= n <= len(lines):
            return lines[n - 1]
        return ""


# --------------------------------------------------------------------------
# Generation
# --------------------------------------------------------------------------

class Generator:
    """Structure-aware sshd_config generator.

    Two modes. 'clean' produces configs that a real sshd is likely to accept,
    which is what makes the differential oracles useful. 'chaos' produces
    hostile input aimed at the invariant oracles.
    """

    def __init__(self, rng: random.Random):
        self.rng = rng

    # -- helpers ---------------------------------------------------------

    def _sep(self, chaos: bool) -> str:
        if chaos:
            return self.rng.choice(SEPARATORS)
        return self.rng.choice([" ", "\t", " ", " "])

    def _directive_line(self, chaos: bool) -> str:
        name = self.rng.choice(DIRECTIVES)
        if chaos and self.rng.random() < 0.35:
            name = self._corrupt_name(name)
        sep = self._sep(chaos)
        if chaos and self.rng.random() < 0.5:
            value = self.rng.choice(TRICKY_VALUES)
        else:
            value = self.rng.choice(BOOL_VALUES + ["22", "2", "10", "INFO",
                                                   "VERBOSE", "sandbox"])
        indent = " " * self.rng.randint(0, 3) if chaos else ""
        trail = " " * self.rng.randint(0, 2) if chaos else ""
        return f"{indent}{name}{sep}{value}{trail}"

    def _corrupt_name(self, name: str) -> str:
        r = self.rng.random()
        if r < 0.25 and len(name) > 3:                      # transpose
            i = self.rng.randrange(len(name) - 1)
            return name[:i] + name[i + 1] + name[i] + name[i + 2:]
        if r < 0.5:                                          # append
            return name + self.rng.choice(["s", "2", "_", "X"])
        if r < 0.7 and len(name) > 3:                        # drop a char
            i = self.rng.randrange(len(name))
            return name[:i] + name[i + 1:]
        if r < 0.85:                                         # case scramble
            return "".join(c.upper() if self.rng.random() < 0.5 else c.lower()
                           for c in name)
        return "".join(self.rng.choice("abcdefghijklmnopqrstuvwxyz")
                       for _ in range(self.rng.randint(1, 20)))

    def _match_block(self, chaos: bool) -> list[str]:
        crit = self.rng.choice([
            "User fuzz", "User *", "Group wheel", "Address 127.0.0.1",
            "Host localhost", "all", "User fuzz Address 127.0.0.1",
        ])
        if chaos and self.rng.random() < 0.3:
            crit = self.rng.choice(["", "User", "Nonsense value", "all extra"])
        out = [f"Match {crit}"]
        for _ in range(self.rng.randint(0, 4)):
            out.append("    " + self._directive_line(chaos))
        return out

    # -- public ----------------------------------------------------------

    def generate(self, chaos: bool) -> Case:
        lines: list[str] = []
        includes: dict[str, bytes] = {}

        # Include block, always before any Match, mirroring real configs.
        if self.rng.random() < 0.35:
            includes, inc_lines = self._make_includes(chaos)
            lines.extend(inc_lines)

        for _ in range(self.rng.randint(1, 25)):
            r = self.rng.random()
            if r < 0.70:
                lines.append(self._directive_line(chaos))
            elif r < 0.80:
                lines.append("")
            elif r < 0.90:
                lines.append("# " + self.rng.choice(
                    ["comment", "PermitRootLogin yes", "", "#" * 40]))
            else:
                lines.extend(self._match_block(chaos))

        body = "\n".join(lines) + "\n"
        data = body.encode("utf-8", errors="replace")

        if chaos:
            data = self._chaos_bytes(data)

        return Case(data, includes, origin="chaos" if chaos else "clean")

    def _make_includes(self, chaos: bool) -> tuple[dict[str, bytes], list[str]]:
        includes: dict[str, bytes] = {}
        lines: list[str] = []
        depth = self.rng.randint(1, 3) if chaos else 1
        for i in range(depth):
            rel = f"sshd_config.d/{i:02d}-fuzz.conf"
            inner = "\n".join(self._directive_line(chaos)
                              for _ in range(self.rng.randint(1, 5))) + "\n"
            includes[rel] = inner.encode("utf-8", errors="replace")
        target = self.rng.choice([
            "sshd_config.d/*.conf",
            "sshd_config.d/00-fuzz.conf",
            "sshd_config.d/**/*.conf" if chaos else "sshd_config.d/*.conf",
        ])
        sep = self._sep(chaos)
        lines.append(f"Include{sep}{target}")
        if chaos and self.rng.random() < 0.3:
            lines.append("Include /nonexistent/path/*.conf")
        return includes, lines

    def _chaos_bytes(self, data: bytes) -> bytes:
        r = self.rng.random()
        if r < 0.10:
            data = b"\xef\xbb\xbf" + data                 # UTF-8 BOM
        elif r < 0.15:
            data = b"\xff\xfe" + data                     # UTF-16 BOM
        if self.rng.random() < 0.15:
            data = data.replace(b"\n", b"\r\n")           # CRLF
        if self.rng.random() < 0.10:
            data = data + bytes(self.rng.randrange(0x80, 0xFF)
                                for _ in range(self.rng.randint(1, 32)))
        if self.rng.random() < 0.05:
            data = data.replace(b"\n", b"", 1)            # no trailing newline
        return data


# --------------------------------------------------------------------------
# Mutation
# --------------------------------------------------------------------------

class Mutator:
    """Line- and byte-level mutations applied to an existing case.

    Mutating real fixtures reaches deep code paths that pure generation
    rarely hits, because the seed already satisfies the parser's happy path.
    """

    def __init__(self, rng: random.Random, gen: Generator):
        self.rng = rng
        self.gen = gen

    def mutate(self, case: Case) -> Case:
        data = case.main
        for _ in range(self.rng.randint(1, 4)):
            data = self._one(data)
        return Case(data, dict(case.includes), origin="mutated")

    def _one(self, data: bytes) -> bytes:
        lines = data.split(b"\n")
        if not lines:
            return data
        r = self.rng.random()

        if r < 0.20:                                       # delete a line
            i = self.rng.randrange(len(lines))
            del lines[i]
        elif r < 0.40:                                     # duplicate a line
            i = self.rng.randrange(len(lines))
            lines.insert(i, lines[i])
        elif r < 0.55:                                     # insert new line
            i = self.rng.randrange(len(lines) + 1)
            lines.insert(i, self.gen._directive_line(True).encode())
        elif r < 0.65:                                     # swap two lines
            if len(lines) > 1:
                i, j = self.rng.sample(range(len(lines)), 2)
                lines[i], lines[j] = lines[j], lines[i]
        elif r < 0.80:                                     # mutate separator
            i = self.rng.randrange(len(lines))
            lines[i] = re.sub(rb"[ \t]+",
                              self.rng.choice(SEPARATORS).encode(),
                              lines[i], count=1)
        elif r < 0.92:                                     # mutate value
            i = self.rng.randrange(len(lines))
            parts = lines[i].split(None, 1)
            if len(parts) == 2:
                lines[i] = parts[0] + b" " + \
                    self.rng.choice(TRICKY_VALUES).encode("utf-8", "replace")
        else:                                              # byte flip
            if data:
                i = self.rng.randrange(len(data))
                b = bytes([self.rng.randrange(256)])
                return data[:i] + b + data[i + 1:]

        return b"\n".join(lines)


def load_corpus(paths: list[str]) -> list[Case]:
    """Load seed configs from files or directories."""
    cases: list[Case] = []
    for p in paths:
        if os.path.isdir(p):
            files = sorted(globmod.glob(os.path.join(p, "**", "*"),
                                        recursive=True))
        else:
            files = [p]
        for f in files:
            if not os.path.isfile(f):
                continue
            if os.path.getsize(f) > 1 << 20:
                continue
            with open(f, "rb") as fh:
                cases.append(Case(fh.read(), origin=f"corpus:{f}"))
    return cases


# --------------------------------------------------------------------------
# Running the target
# --------------------------------------------------------------------------

class Result:
    def __init__(self, code, stdout, stderr, elapsed, timed_out):
        self.code = code
        self.stdout = stdout
        self.stderr = stderr
        self.elapsed = elapsed
        self.timed_out = timed_out


def run_target(argv: list[str], cwd: str, timeout: float) -> Result:
    start = time.monotonic()
    try:
        proc = subprocess.run(argv, cwd=cwd, capture_output=True,
                              timeout=timeout)
        return Result(proc.returncode, proc.stdout, proc.stderr,
                      time.monotonic() - start, False)
    except subprocess.TimeoutExpired:
        return Result(None, b"", b"", time.monotonic() - start, True)


TRACEBACK_MARKERS = (
    b"Traceback (most recent call last)",
    b"\nRecursionError",
    b"\nUnicodeDecodeError",
    b"\nUnicodeEncodeError",
    b"\nMemoryError",
)


# --------------------------------------------------------------------------
# Finding extraction (schema-tolerant)
# --------------------------------------------------------------------------

_RULE_KEYS = ("rule", "rule_id", "ruleid", "id", "code", "check")
_LINE_KEYS = ("line", "lineno", "line_number", "linenum", "row")
_FILE_KEYS = ("file", "path", "filename", "source")


def iter_findings(obj):
    """Walk arbitrary JSON and yield anything that looks like a finding."""
    if isinstance(obj, dict):
        has_rule = any(k in obj for k in _RULE_KEYS)
        has_loc = any(k in obj for k in _LINE_KEYS + ("message", "msg", "text",
                                                      "title", "description"))
        if has_rule and has_loc:
            yield obj
        for v in obj.values():
            yield from iter_findings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from iter_findings(v)


def finding_rule_number(f) -> int | None:
    for k in _RULE_KEYS:
        if k in f:
            digits = re.findall(r"\d+", str(f[k]))
            if digits:
                return int(digits[-1])
    return None


def finding_line(f) -> int | None:
    for k in _LINE_KEYS:
        v = f.get(k)
        if isinstance(v, int):
            return v
        if isinstance(v, str) and v.isdigit():
            return int(v)
    return None


def finding_file(f) -> str | None:
    for k in _FILE_KEYS:
        v = f.get(k)
        if isinstance(v, str):
            return v
    return None


# --------------------------------------------------------------------------
# sshd oracle support
# --------------------------------------------------------------------------

class SshdOracle:
    """Wraps the real sshd binary as a reference implementation."""

    # sshd failures unrelated to the config under test. Treated as
    # inconclusive rather than as disagreement, so the fuzzer stays honest.
    INCONCLUSIVE = (
        "host key", "hostkey", "permission denied", "no such user",
        "getpwnam", "privilege separation", "must be owned by root",
        "bad ownership", "unable to load", "could not load host key",
        "setgroups", "operation not permitted",
    )

    def __init__(self, workdir: str, sshd: str | None = None):
        self.sshd = sshd or self._locate()
        self.available = self.sshd is not None
        self.hostkey = None
        self.vocabulary: set[str] = set()
        if self.available:
            self.hostkey = self._make_hostkey(workdir)
            self.vocabulary = self._probe_vocabulary(workdir)
            if not self.vocabulary:
                self.available = False

    @staticmethod
    def _locate() -> str | None:
        for cand in ("sshd",):
            found = shutil.which(cand)
            if found:
                return found
        for cand in ("/usr/sbin/sshd", "/usr/bin/sshd", "/sbin/sshd"):
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                return cand
        return None

    def _make_hostkey(self, workdir: str) -> str | None:
        keygen = shutil.which("ssh-keygen")
        if not keygen:
            return None
        path = os.path.join(workdir, "fuzz_hostkey")
        if os.path.exists(path):
            return path
        try:
            subprocess.run([keygen, "-q", "-t", "ed25519", "-N", "",
                            "-f", path], check=True, capture_output=True,
                           timeout=30)
            os.chmod(path, 0o600)
            return path
        except Exception:
            return None

    def _base_args(self) -> list[str]:
        args = [self.sshd]
        if self.hostkey:
            # Command-line -o is parsed first and sshd is first-wins, so this
            # overrides any HostKey in the config under test.
            args += ["-o", f"HostKey={self.hostkey}"]
        # -C is required for -T to evaluate Match blocks.
        args += ["-C", "user=fuzz,host=localhost,addr=127.0.0.1"]
        return args

    def _probe_vocabulary(self, workdir: str) -> set[str]:
        """Directive universe, from a dump of sshd's own defaults."""
        empty = os.path.join(workdir, "empty.conf")
        with open(empty, "w") as fh:
            fh.write("")
        try:
            proc = subprocess.run(self._base_args() + ["-T", "-f", empty],
                                  capture_output=True, timeout=30)
        except Exception:
            return set()
        if proc.returncode != 0:
            return set()
        vocab = set()
        for line in proc.stdout.decode("utf-8", "replace").splitlines():
            tok = line.split(None, 1)
            if tok:
                vocab.add(tok[0].strip().lower())
        vocab |= SSHD_T_OMITTED
        return vocab

    def _inconclusive(self, stderr: bytes) -> bool:
        low = stderr.decode("utf-8", "replace").lower()
        return any(m in low for m in self.INCONCLUSIVE)

    def check(self, cfg_path: str, timeout: float):
        """Return (verdict, stderr) where verdict is True/False/None."""
        try:
            proc = subprocess.run(self._base_args() + ["-t", "-f", cfg_path],
                                  capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return None, b"sshd timed out"
        except Exception as exc:
            return None, str(exc).encode()
        if proc.returncode != 0 and self._inconclusive(proc.stderr):
            return None, proc.stderr
        return proc.returncode == 0, proc.stderr

    def dump(self, cfg_path: str, timeout: float) -> dict[str, list[str]] | None:
        """Normalised `sshd -T` output, or None if the config was rejected."""
        try:
            proc = subprocess.run(self._base_args() + ["-T", "-f", cfg_path],
                                  capture_output=True, timeout=timeout)
        except Exception:
            return None
        if proc.returncode != 0:
            return None
        out: dict[str, list[str]] = {}
        for line in proc.stdout.decode("utf-8", "replace").splitlines():
            parts = line.split(None, 1)
            if not parts:
                continue
            key = parts[0].lower()
            val = parts[1] if len(parts) > 1 else ""
            out.setdefault(key, []).append(val)
        return out


# --------------------------------------------------------------------------
# Oracles
# --------------------------------------------------------------------------

class Failure(Exception):
    def __init__(self, oracle: str, detail: str):
        super().__init__(f"[{oracle}] {detail}")
        self.oracle = oracle
        self.detail = detail


def oracle_invariants(res: Result, res2: Result, timeout: float):
    if res.timed_out:
        raise Failure("TIMEOUT",
                      f"no exit within {timeout}s -- possible pathological loop")

    if any(m in res.stderr for m in TRACEBACK_MARKERS):
        tail = res.stderr.decode("utf-8", "replace").strip().splitlines()[-6:]
        raise Failure("TRACEBACK", "uncaught exception:\n  " + "\n  ".join(tail))

    if res.code not in ALLOWED_EXIT_CODES:
        raise Failure("EXITCODE",
                      f"exit {res.code} not in {sorted(ALLOWED_EXIT_CODES)}")

    if res2.code != res.code or res2.stdout != res.stdout:
        raise Failure("NONDETERMINISM",
                      f"two identical runs diverged "
                      f"(exit {res.code} vs {res2.code}, "
                      f"stdout {len(res.stdout)} vs {len(res2.stdout)} bytes)")


def oracle_json(res: Result):
    """--json output must always be parseable and structurally stable."""
    if res.code in OPERATIONAL_ERROR_CODES:
        return None                       # refused to analyse; no JSON expected
    if not res.stdout.strip():
        raise Failure("JSON", f"empty stdout with exit {res.code}")
    try:
        doc = json.loads(res.stdout.decode("utf-8"))
    except Exception as exc:
        head = res.stdout[:200].decode("utf-8", "replace")
        raise Failure("JSON", f"unparseable output: {exc}\n  head: {head!r}")
    if not isinstance(doc, (dict, list)):
        raise Failure("JSON", f"top level is {type(doc).__name__}, expected object or array")
    return doc


def oracle_diff_validity(sshd_ok, res: Result, sshd_err: bytes):
    """D1: sshd accepting a config means the linter must be able to read it."""
    if sshd_ok is not True:
        return
    if res.code in OPERATIONAL_ERROR_CODES:
        detail = res.stderr.decode("utf-8", "replace").strip()[:300]
        raise Failure("DIFF-VALIDITY",
                      f"sshd -t accepts this config but linter exited "
                      f"{res.code}\n  linter stderr: {detail}")


def oracle_diff_vocabulary(doc, case: Case, vocab: set[str], main_name: str):
    """D2: rule 58 must not fire on a directive that sshd itself knows."""
    if doc is None or not vocab:
        return
    for f in iter_findings(doc):
        if finding_rule_number(f) != RULE_UNKNOWN_DIRECTIVE:
            continue
        fname = finding_file(f)
        if fname and os.path.basename(fname) != main_name:
            continue                       # finding is in an included file
        n = finding_line(f)
        if n is None:
            continue
        raw = case.line(n).strip()
        if not raw or raw.startswith("#"):
            continue
        token = re.split(r"[\s=]+", raw, maxsplit=1)[0].strip().lower()
        if token and token in vocab:
            raise Failure("DIFF-VOCAB",
                          f"rule {RULE_UNKNOWN_DIRECTIVE} flagged {token!r} "
                          f"(line {n}) as unknown, but sshd accepts it\n"
                          f"  line: {raw[:120]!r}")


def oracle_adapter(case: Case, cfg_path: str, dump: dict[str, list[str]] | None):
    """Optional value-level differential. Inert until the adapter is wired."""
    parsed = parse_config_adapter(cfg_path)
    if parsed is None or dump is None:
        return
    for key, want in dump.items():
        if key in SSHD_T_OMITTED or key not in parsed:
            continue
        got = parsed[key]
        if [v.strip().lower() for v in got] != [v.strip().lower() for v in want]:
            raise Failure("DIFF-VALUE",
                          f"directive {key!r}: linter parsed {got!r}, "
                          f"sshd -T reports {want!r}")


def parse_config_adapter(cfg_path: str) -> dict[str, list[str]] | None:
    """Wire this to the linter's parser to enable value-level diffing.

    Return a mapping of lowercase directive name -> list of effective values,
    matching `sshd -T` semantics (first-wins for scalars, all values in order
    for cumulative directives). Return None to leave this oracle disabled.

    Example:

        from sshd_lint import parse_file          # adjust to the real API
        cfg = parse_file(cfg_path)
        out = {}
        for directive in cfg.directives:
            out.setdefault(directive.name.lower(), []).append(directive.value)
        return out
    """
    return None


# --------------------------------------------------------------------------
# Crash reporting
# --------------------------------------------------------------------------

def save_crash(outdir: str, case: Case, failure: Failure, argv: list[str],
               res: Result, iteration: int, seed: int) -> str:
    cid = f"{failure.oracle.lower()}-{case.digest()}"
    path = os.path.join(outdir, cid)
    os.makedirs(path, exist_ok=True)
    case.materialise(path)

    with open(os.path.join(path, "report.txt"), "w") as fh:
        fh.write(f"oracle    : {failure.oracle}\n")
        fh.write(f"iteration : {iteration}\n")
        fh.write(f"seed      : {seed}\n")
        fh.write(f"origin    : {case.origin}\n")
        fh.write(f"exit code : {res.code}\n")
        fh.write(f"elapsed   : {res.elapsed:.3f}s\n\n")
        fh.write(f"{failure.detail}\n\n")
        fh.write("--- stdout ---\n")
        fh.write(res.stdout.decode("utf-8", "replace")[:8000])
        fh.write("\n--- stderr ---\n")
        fh.write(res.stderr.decode("utf-8", "replace")[:8000])

    repro = os.path.join(path, "repro.sh")
    cmd = " ".join(shlex.quote(a) for a in argv[:-1])
    with open(repro, "w") as fh:
        fh.write("#!/bin/sh\n")
        fh.write("# Reproduce from the directory containing this script.\n")
        fh.write('cd "$(dirname "$0")" || exit 1\n')
        fh.write(f"{cmd} sshd_config\n")
        fh.write("echo \"exit: $?\"\n")
    os.chmod(repro, 0o755)
    return path


# --------------------------------------------------------------------------
# Main loop
# --------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        prog="fuzz_diff.py",
        description="Structure-aware and differential fuzzer for sshd-lint.")
    ap.add_argument("-n", "--iterations", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=0,
                    help="RNG seed; runs are fully reproducible")
    ap.add_argument("--target", default=DEFAULT_TARGET,
                    help=f"how to invoke the linter (default: {DEFAULT_TARGET!r})")
    ap.add_argument("--json-flag", default="--json",
                    help="flag that selects JSON output")
    ap.add_argument("--corpus", action="append", default=[],
                    help="seed file or directory; repeatable")
    ap.add_argument("--base-dir-flag", default="--base-dir",
                    help="flag that sets the Include base directory")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    ap.add_argument("--no-sshd", action="store_true",
                    help="skip differential oracles")
    ap.add_argument("--sshd", default=None, help="path to the sshd binary")
    ap.add_argument("--crashes", default="tests/fuzz-crashes")
    ap.add_argument("--keep-going", action="store_true",
                    help="do not stop at the first failure")
    ap.add_argument("--quick", action="store_true",
                    help="short run suitable for a pre-release gate")
    args = ap.parse_args()

    if args.quick:
        args.iterations = min(args.iterations, 300)

    rng = random.Random(args.seed)
    gen = Generator(rng)
    mut = Mutator(rng, gen)
    seeds = load_corpus(args.corpus) if args.corpus else []

    target_argv = shlex.split(args.target)
    workdir = tempfile.mkdtemp(prefix="sshd-lint-fuzz-")

    sshd = SshdOracle(workdir, args.sshd) if not args.no_sshd \
        else SshdOracle.__new__(SshdOracle)
    if args.no_sshd:
        sshd.available = False
        sshd.vocabulary = set()

    print(f"target      : {args.target}")
    print(f"seed        : {args.seed}")
    print(f"iterations  : {args.iterations}")
    print(f"corpus      : {len(seeds)} seed file(s)")
    if sshd.available:
        print(f"sshd oracle : {sshd.sshd} "
              f"({len(sshd.vocabulary)} known directives)")
    else:
        print("sshd oracle : disabled "
              "(binary unavailable or -T probe failed)")
    print()

    failures = 0
    inconclusive = 0
    diff_checked = 0
    slowest = 0.0
    t0 = time.monotonic()

    for i in range(1, args.iterations + 1):
        # Alternate between fresh generation and corpus mutation, and between
        # clean and hostile input.
        if seeds and rng.random() < 0.4:
            case = mut.mutate(rng.choice(seeds))
        else:
            case = gen.generate(chaos=rng.random() < 0.5)

        rundir = os.path.join(workdir, "case")
        shutil.rmtree(rundir, ignore_errors=True)
        os.makedirs(rundir, exist_ok=True)
        cfg = case.materialise(rundir)

        argv = list(target_argv) + [args.json_flag]
        if case.includes:
            argv += [args.base_dir_flag, rundir]
        argv.append(cfg)

        res = run_target(argv, rundir, args.timeout)
        res2 = run_target(argv, rundir, args.timeout) if not res.timed_out \
            else res
        slowest = max(slowest, res.elapsed)

        try:
            oracle_invariants(res, res2, args.timeout)
            doc = oracle_json(res)

            if sshd.available:
                verdict, err = sshd.check(cfg, args.timeout)
                if verdict is None:
                    inconclusive += 1
                else:
                    diff_checked += 1
                    oracle_diff_validity(verdict, res, err)
                    oracle_diff_vocabulary(doc, case, sshd.vocabulary,
                                           os.path.basename(cfg))
                    if verdict:
                        oracle_adapter(case, cfg, sshd.dump(cfg, args.timeout))

        except Failure as f:
            failures += 1
            path = save_crash(args.crashes, case, f, argv, res, i, args.seed)
            print(f"FAIL  iter {i}  {f}")
            print(f"      saved: {path}\n")
            if not args.keep_going:
                break

        if i % 250 == 0:
            rate = i / max(time.monotonic() - t0, 1e-9)
            print(f"  {i}/{args.iterations}  "
                  f"{rate:.0f} exec/s  failures={failures}")

    shutil.rmtree(workdir, ignore_errors=True)

    elapsed = time.monotonic() - t0
    print()
    print(f"elapsed        : {elapsed:.1f}s")
    print(f"slowest run    : {slowest:.2f}s")
    if sshd.available:
        print(f"differential   : {diff_checked} compared, "
              f"{inconclusive} inconclusive")
    print(f"failures       : {failures}")
    print("RESULT         : " + ("PASS" if failures == 0 else "FAIL"))
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
