"""Regression tests: the parser must read a config the way sshd does.

Every case here was checked against `sshd -T` (OpenSSH 9.6): sshd ran with
PermitRootLogin yes while the linter used to report no CRITICAL finding.

Run from the repository root with the standard library only:
    PYTHONPATH=src python3 -m unittest discover -s tests
"""

import json
import tempfile
import unittest
from pathlib import Path

from sshd_lint import (
    Finding,
    RuleEngine,
    Severity,
    SshdConfigParser,
    report_json,
    report_text,
)


def _lint(data: bytes, extra: "dict[str, bytes] | None" = None) -> list:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for name, content in (extra or {}).items():
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_bytes(content.replace(b"@ROOT@", str(root).encode()))
        cfg = root / "sshd_config"
        cfg.write_bytes(data.replace(b"@ROOT@", str(root).encode()))
        parser = SshdConfigParser(cfg, root)
        parser.parse()
        return RuleEngine(parser).run()


def _root_login(findings: list) -> list:
    return [(f.severity, f.match_scope) for f in findings
            if f.directive == "PermitRootLogin"]


class RootLoginIsSeen(unittest.TestCase):
    CASES = {
        # sshd copies lines with strlen(): the NUL ends the value there.
        "nul_after_value": b"PermitRootLogin yes\x00\n\n",
        # Only '\n' ends a line for sshd; these stay inside the comment.
        "formfeed_in_comment": b"# x\x0cPermitRootLogin no\nPermitRootLogin yes\n",
        "u2028_in_comment": "# x PermitRootLogin no\nPermitRootLogin yes\n".encode(),
        "cr_in_comment": b"# x\rPermitRootLogin no\nPermitRootLogin yes\n",
        "phantom_match": b"# x\x0cMatch User nobody\nPermitRootLogin yes\n",
        # strdelim() unquotes the keyword; argv_split() unquotes values.
        "quoted_keyword": b'"PermitRootLogin" yes\n',
        "mid_quoted_keyword": b'Permit"RootLogin" yes\n',
        "single_quoted_value": b"PermitRootLogin 'yes'\n",
        "partial_quotes": b'PermitRootLogin "y"es\n',
        "empty_quotes": b'PermitRootLogin ye""s\n',
    }

    def test_cases(self):
        for name, data in self.CASES.items():
            with self.subTest(name):
                self.assertIn((Severity.CRITICAL, None), _root_login(_lint(data)))

    def test_quoted_include_keyword(self):
        findings = _lint(b'"Include" @ROOT@/inc.conf\n',
                         {"inc.conf": b"PermitRootLogin yes\n"})
        self.assertIn((Severity.CRITICAL, None), _root_login(findings))

    def test_include_path_with_space(self):
        findings = _lint(b'Include "@ROOT@/my dir.conf"\n',
                         {"my dir.conf": b"PermitRootLogin yes\n"})
        self.assertIn((Severity.CRITICAL, None), _root_login(findings))


class NoPhantomFindings(unittest.TestCase):
    def test_nul_merges_into_next_line(self):
        # sshd reads '#' + 'PermitRootLogin yes' as one comment line.
        findings = _lint(b"#\x00\nPermitRootLogin yes\n")
        self.assertNotIn((Severity.CRITICAL, None), _root_login(findings))

    def test_multi_argument_value_is_kept(self):
        parser_findings = _lint(b'AllowUsers "user one" two\n')
        self.assertFalse([f for f in parser_findings
                          if f.directive == "AllowUsers / AllowGroups"])

    def test_crlf_file(self):
        findings = _lint(b"PermitRootLogin yes\r\n")
        self.assertIn((Severity.CRITICAL, None), _root_login(findings))


class MatchScopeAcrossIncludes(unittest.TestCase):
    """Match state as sshd -T (OpenSSH 9.6) reports it."""

    def test_match_in_included_file_ends_with_it(self):
        # servconf.c restores the parent's Match state after an Include.
        findings = _lint(
            b"Include @ROOT@/d/*.conf\nPermitRootLogin yes\n",
            {"d/20.conf": b"Match Address 10.0.0.0/8\n    X11Forwarding yes\n"},
        )
        self.assertIn((Severity.CRITICAL, None), _root_login(findings))

    def test_quoted_match_all(self):
        findings = _lint(b'Match User bob\n    X11Forwarding yes\n'
                         b'Match "all"\nPermitRootLogin yes\nCiphers 3des-cbc\n')
        self.assertIn((Severity.CRITICAL, None), _root_login(findings))
        self.assertTrue([f for f in findings if f.directive == "Ciphers"])

    def test_line_after_match_all_overrides_global(self):
        findings = _lint(b"PermitRootLogin no\nMatch User bob\n"
                         b"    X11Forwarding yes\nMatch all\nPermitRootLogin yes\n")
        self.assertIn((Severity.CRITICAL, None), _root_login(findings))

    def test_non_match_keyword_after_match_all_stays_first_wins(self):
        findings = _lint(b"LoginGraceTime 30\nMatch all\nLoginGraceTime 600\n")
        self.assertFalse([f for f in findings
                          if f.directive == "LoginGraceTime" and f.line == 3
                          and f.severity == Severity.LOW])

    def test_file_included_under_match_then_globally(self):
        findings = _lint(
            b"Match User nobody\n    Include @ROOT@/x.conf\n"
            b"Match all\nInclude @ROOT@/x.conf\n",
            {"x.conf": b"PermitRootLogin yes\n"},
        )
        self.assertIn((Severity.CRITICAL, None), _root_login(findings))

    def test_match_all_in_file_included_from_match(self):
        # Such a file is parsed with SSHCFG_NEVERMATCH: its 'Match all'
        # returns to the enclosing Match, not to global scope.
        findings = _lint(
            b"Match User alice\n    Include @ROOT@/in.conf\n"
            b"Match all\nPermitRootLogin yes\n",
            {"in.conf": b"Match all\nPermitRootLogin no\n"},
        )
        self.assertIn((Severity.CRITICAL, None), _root_login(findings))


class IncludeExpansion(unittest.TestCase):
    def test_double_star_is_not_recursive(self):
        # glob(3) reads '**' as '*': sshd never reads d/00.conf here.
        findings = _lint(
            b"Include @ROOT@/d/**/*.conf\n",
            {"d/00.conf": b"PermitRootLogin no\n",
             "d/sub/10.conf": b"PermitRootLogin yes\n"},
        )
        self.assertIn((Severity.CRITICAL, None), _root_login(findings))

    def test_deep_include_chain_is_reported_not_crashed(self):
        extra = {f"{i}.conf": f"Include @ROOT@/{i + 1}.conf\n".encode()
                 for i in range(1, 1200)}
        findings = _lint(b"Include @ROOT@/1.conf\n", extra)
        self.assertTrue([f for f in findings if f.severity == Severity.CRITICAL
                         and "nested more than 16" in f.message])

    def test_sixteen_levels_are_allowed(self):
        extra = {f"{i}.conf": f"Include @ROOT@/{i + 1}.conf\n".encode()
                 for i in range(1, 16)}
        extra["16.conf"] = b"PermitRootLogin yes\n"
        findings = _lint(b"Include @ROOT@/1.conf\n", extra)
        self.assertIn((Severity.CRITICAL, None), _root_login(findings))


class RuleValues(unittest.TestCase):
    def test_wildcard_host_key_algorithms(self):
        for line in (b"HostKeyAlgorithms ssh-*\n",
                     b"PubkeyAcceptedAlgorithms +ssh-rsa*\n"):
            with self.subTest(line):
                self.assertTrue([f for f in _lint(line)
                                 if f.severity == Severity.HIGH
                                 and "algorithm" in f.message])

    def test_max_startups_last_wins(self):
        findings = _lint(b"MaxStartups 10:30:60\nMaxStartups 10:30:1000\n")
        self.assertTrue([f for f in findings if f.directive == "MaxStartups"
                         and f.line == 2 and "very high" in f.message])

    def test_setenv_is_first_line_wins(self):
        findings = _lint(b"SetEnv A=1\nSetEnv B=2\n")
        self.assertTrue([f for f in findings
                         if f.directive == "SetEnv" and f.line == 2])

    def test_allow_tcp_forwarding_all(self):
        findings = _lint(b"AllowTcpForwarding all\n")
        self.assertTrue([f for f in findings
                         if f.directive == "AllowTcpForwarding"])


class TextReportIsInert(unittest.TestCase):
    def test_escape_sequences_are_not_emitted(self):
        finding = Finding(
            severity=Severity.MEDIUM, directive="X11Forwarding", value="yes",
            message="m \x1b[2J", detail="d", match_scope="User x\x1b[2J\x9b",
        )
        out = report_text([finding], use_color=False)
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\x9b", out)
        self.assertIn("\\x1b[2J", out)

    def test_newline_in_file_name_is_escaped(self):
        finding = Finding(
            severity=Severity.MEDIUM, directive="X11Forwarding", value="yes",
            message="m", detail="d", line=1,
            source=Path("/d/a\n[CRITICAL] fake.conf"),
        )
        out = report_text([finding], use_color=False)
        self.assertNotIn("\n[CRITICAL]", out)

    def test_json_escapes_c1_controls(self):
        finding = Finding(
            severity=Severity.MEDIUM, directive="X11Forwarding", value="yes",
            message="m", detail="d", match_scope="User x\x9b2J",
        )
        out = report_json([finding], 1)
        self.assertNotIn("\x9b", out)
        self.assertEqual(json.loads(out)["findings"][0]["scope"],
                         "User x\x9b2J")


if __name__ == "__main__":
    unittest.main()
