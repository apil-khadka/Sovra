#!/usr/bin/env python3
"""No-network regression for the live-planning smoke's guard gate.

Pins guard_mismatch (strict positive acceptance) without touching any
stack, container, or provider: rejected, malformed, and wrong-code
verdicts must mismatch, and only accepted+expected passes.

Run: python3 scripts/smoke_live_planning_test.py
"""

import importlib.util
import unittest
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parent / "smoke-live-planning.py"
_SPEC = importlib.util.spec_from_file_location("smoke_live_planning", _SCRIPT)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)


class GuardMismatchTests(unittest.TestCase):
    def test_accepted_with_expected_code_passes(self):
        self.assertIsNone(
            _MODULE.guard_mismatch(
                {"accepted": True, "code": "GUARD_ACCEPTED"}, "GUARD_ACCEPTED"))

    def test_rejected_verdict_mismatches(self):
        reason = _MODULE.guard_mismatch(
            {"accepted": False, "code": "GUARD_MISSING_CITATION"}, "GUARD_ACCEPTED")
        self.assertIsNotNone(reason)
        self.assertIn("did not accept", reason)

    def test_accepted_with_wrong_code_mismatches(self):
        reason = _MODULE.guard_mismatch(
            {"accepted": True, "code": "SOMETHING_ELSE"}, "GUARD_ACCEPTED")
        self.assertIsNotNone(reason)
        self.assertIn("GUARD_ACCEPTED", reason)

    def test_malformed_verdicts_mismatch(self):
        for verdict in (None, [], "GUARD_ACCEPTED", {}, {"accepted": True},
                        {"code": "GUARD_ACCEPTED"}, {"accepted": "yes",
                                                    "code": "GUARD_ACCEPTED"}):
            with self.subTest(verdict=verdict):
                self.assertIsNotNone(
                    _MODULE.guard_mismatch(verdict, "GUARD_ACCEPTED"))

    def test_custom_expected_code_is_honored(self):
        self.assertIsNone(
            _MODULE.guard_mismatch(
                {"accepted": True, "code": "CUSTOM_OK"}, "CUSTOM_OK"))
        self.assertIsNotNone(
            _MODULE.guard_mismatch(
                {"accepted": True, "code": "GUARD_ACCEPTED"}, "CUSTOM_OK"))


if __name__ == "__main__":
    unittest.main()
