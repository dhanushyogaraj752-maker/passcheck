import math
import unittest

from passcheck import analyze_password


class AnalyzePasswordTests(unittest.TestCase):
    def test_empty_password_is_weak_and_fails_policy(self):
        assessment = analyze_password("")
        self.assertEqual((assessment.score, assessment.label), (0, "Weak"))
        self.assertFalse(any(passed for _, passed in assessment.policy_checks))

    def test_common_password_is_rejected(self):
        assessment = analyze_password("Password")
        self.assertEqual(assessment.score, 0)
        self.assertTrue(assessment.dictionary_match)
        self.assertTrue(any("dictionary" in item for item in assessment.suggestions))

    def test_long_varied_password_meets_policy_and_is_exceptional(self):
        assessment = analyze_password("N7!vQ2#rLm8@xP4z")
        self.assertEqual((assessment.score, assessment.label), (3, "Exceptional"))
        self.assertGreaterEqual(assessment.entropy_bits, 70)
        self.assertTrue(all(passed for _, passed in assessment.policy_checks))

    def test_short_password_gets_length_guidance(self):
        assessment = analyze_password("Ab3!")
        self.assertEqual(assessment.label, "Weak")
        self.assertTrue(any("12 characters" in item for item in assessment.suggestions))

    def test_obvious_sequences_reduce_score(self):
        assessment = analyze_password("Abcdef1234!XYZ")
        self.assertTrue(any("sequences" in item for item in assessment.suggestions))
        self.assertEqual(assessment.score, 0)

    def test_leetspeak_dictionary_variant_is_detected(self):
        assessment = analyze_password("P@ssw0rd123!")
        self.assertTrue(assessment.dictionary_match)
        self.assertEqual(assessment.label, "Weak")

    def test_numeric_dictionary_password_is_detected(self):
        self.assertTrue(analyze_password("123456").dictionary_match)

    def test_entropy_uses_observed_character_classes(self):
        assessment = analyze_password("abc")
        self.assertAlmostEqual(assessment.entropy_bits, 3 * math.log2(26))


if __name__ == "__main__":
    unittest.main()