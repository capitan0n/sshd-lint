"""Regression tests: the parser must read a config the way sshd does.

Every case here was checked against `sshd -T` (OpenSSH 9.6): sshd ran with
PermitRootLogin yes while the linter used to report no CRITICAL finding.

Run from the repository root with the standard library only:
    PYTHONPATH=src python3 -m unittest discover -s tests
"""

import tempfile
import unittest
from pathlib import Path

from sshd_lint import (
    Finding,
    RuleEngine,
    Severity,
    SshdConfigParser,
    report_text,
)


def _lint(data: bytes, extra: "dict[str, bytes] | None" = None) -> list:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for name, content in (extra or {}).items():
            (root / name).write_bytes(content)
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


if __name__ == "__main__":
    unittest.main()
