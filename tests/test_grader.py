"""Grader unit tests. Stdlib unittest, no external runner needed:

    python -m unittest discover -s tests -v
"""
import unittest

from draghunt.schema import GroundTruth, Verdict
from draghunt.grader import grade, WRONG_POLARITY_CAP


def gt(**over):
    base = dict(
        scenario_id="EX-01", technique="T1110.001", tactic="credential-access",
        source_ip="203.0.113.7", account="svc-backup", succeeded=True,
        disposition="malicious",
    )
    base.update(over)
    return GroundTruth(**base)


def vd(**over):
    base = dict(disposition="malicious")
    base.update(over)
    return Verdict(**base)


class TestGrader(unittest.TestCase):
    def test_perfect_verdict_scores_100(self):
        r = grade(gt(), vd(technique="T1110.001", source_ip="203.0.113.7",
                            account="svc-backup", succeeded=True))
        self.assertEqual(r.total, 100.0)
        self.assertFalse(r.capped)
        self.assertTrue(r.band.startswith("A"))

    def test_parent_technique_gets_partial(self):
        r = grade(gt(), vd(technique="T1110", source_ip="203.0.113.7",
                           account="svc-backup", succeeded=True))
        tech = next(i for i in r.items if i.dimension == "technique")
        self.assertGreater(tech.earned, 0)
        self.assertLess(tech.earned, tech.weight)

    def test_wrong_technique_zero(self):
        r = grade(gt(), vd(technique="T1059", source_ip="203.0.113.7",
                           account="svc-backup", succeeded=True))
        tech = next(i for i in r.items if i.dimension == "technique")
        self.assertEqual(tech.earned, 0.0)

    def test_inverted_polarity_is_capped(self):
        # Everything else perfect, but calls a malicious case benign.
        r = grade(gt(), vd(disposition="benign", technique="T1110.001",
                           source_ip="203.0.113.7", account="svc-backup",
                           succeeded=True))
        self.assertTrue(r.capped)
        self.assertLessEqual(r.total, WRONG_POLARITY_CAP)

    def test_inconclusive_not_capped(self):
        r = grade(gt(), vd(disposition="inconclusive", source_ip="203.0.113.7"))
        self.assertFalse(r.capped)

    def test_unobservable_account_has_zero_weight(self):
        r = grade(gt(account=None), vd(source_ip="203.0.113.7", succeeded=True))
        acct = next(i for i in r.items if i.dimension == "account")
        self.assertEqual(acct.weight, 0)
        self.assertEqual(acct.earned, 0)

    def test_partial_verdict_scores_without_error(self):
        r = grade(gt(), vd())  # disposition only
        self.assertGreater(r.total, 0)
        self.assertLess(r.total, 100)

    def test_account_case_insensitive(self):
        r = grade(gt(), vd(account="SVC-Backup", source_ip="203.0.113.7"))
        acct = next(i for i in r.items if i.dimension == "account")
        self.assertEqual(acct.earned, acct.weight)


if __name__ == "__main__":
    unittest.main()
