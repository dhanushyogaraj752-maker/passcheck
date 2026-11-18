"""A local password policy and strength checker."""

from __future__ import annotations

import argparse
import getpass
import math
import re
import string
from dataclasses import dataclass


_COMMON_PASSWORDS = frozenset(
    {
        "123456",
        "123456789",
        "abc123",
        "admin",
        "ashley",
        "dragon",
        "football",
        "iloveyou",
        "letmein",
        "login",
        "master",
        "michael",
        "monkey",
        "password",
        "princess",
        "qwerty",
        "secret",
        "shadow",
        "sunshine",
        "welcome",
    }
)
_LEET_TRANSLATION = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_LABELS = ("Weak", "Moderate", "Strong", "Exceptional")
_POLICY_MIN_LENGTH = 12


@dataclass(frozen=True)
class PasswordAssessment:
    score: int
    label: str
    entropy_bits: float
    policy_checks: tuple[tuple[str, bool], ...]
    dictionary_match: bool
    suggestions: tuple[str, ...]


def _has_sequence(password: str) -> bool:
    lowered = password.lower()
    for start in range(len(lowered) - 3):
        sample = lowered[start : start + 4]
        if all(char in string.ascii_lowercase for char in sample) or all(
            char in string.digits for char in sample
        ):
            if all(
                ord(sample[index + 1]) - ord(sample[index]) == 1
                for index in range(3)
            ) or all(
                ord(sample[index + 1]) - ord(sample[index]) == -1
                for index in range(3)
            ):
                return True
    return False


def _dictionary_match(password: str) -> bool:
    raw_compact = "".join(
        char
        for char in password.lower()
        if char in string.ascii_lowercase + string.digits
    )
    compact = "".join(
        char
        for char in password.lower().translate(_LEET_TRANSLATION)
        if char in string.ascii_lowercase + string.digits
    )
    normalized = "".join(
        char
        for char in compact
        if char in string.ascii_lowercase
    )
    return raw_compact in _COMMON_PASSWORDS or any(
        entry in normalized for entry in _COMMON_PASSWORDS if entry.isalpha()
    )


def analyze_password(password: str) -> PasswordAssessment:
    """Estimate entropy and policy compliance without retaining the password.

    Entropy assumes every character is selected uniformly from the observed
    character classes. Dictionary and pattern checks separately reduce the
    strength rating because that assumption does not hold for those passwords.
    """
    has_lowercase = any(char in string.ascii_lowercase for char in password)
    has_uppercase = any(char in string.ascii_uppercase for char in password)
    has_digit = any(char in string.digits for char in password)
    has_special = any(
        not char.isalnum() and not char.isspace() for char in password
    )

    policy_checks = (
        (f"At least {_POLICY_MIN_LENGTH} characters", len(password) >= _POLICY_MIN_LENGTH),
        ("Lowercase letter", has_lowercase),
        ("Uppercase letter", has_uppercase),
        ("Digit", has_digit),
        ("Special character", has_special),
    )

    character_pool = sum(
        size
        for present, size in (
            (has_lowercase, 26),
            (has_uppercase, 26),
            (has_digit, 10),
            (has_special, 32),
        )
        if present
    )
    entropy_bits = len(password) * math.log2(character_pool) if character_pool else 0.0
    dictionary_match = _dictionary_match(password)
    has_obvious_pattern = bool(re.search(r"(.)\1{2,}", password)) or _has_sequence(password)

    score = (
        0
        if entropy_bits < 28
        else 1
        if entropy_bits < 50
        else 2
        if entropy_bits < 70
        else 3
    )
    if not all(passed for _, passed in policy_checks):
        score = min(score, 1)
    if dictionary_match or has_obvious_pattern:
        score = 0

    suggestions = []
    for requirement, passed in policy_checks:
        if not passed:
            if requirement.startswith("At least"):
                suggestions.append("Use at least 12 characters; a longer passphrase is easier to remember.")
            else:
                suggestions.append(f"Add a {requirement.lower()} to meet the password policy.")
    if dictionary_match:
        suggestions.append("Avoid common or dictionary passwords, including simple character substitutions.")
    if has_obvious_pattern:
        suggestions.append("Avoid repeated characters and obvious sequences such as 1234 or abcd.")
    if not suggestions:
        suggestions.append("Use a unique password for every account.")

    return PasswordAssessment(
        score=score,
        label=_LABELS[score],
        entropy_bits=entropy_bits,
        policy_checks=policy_checks,
        dictionary_match=dictionary_match,
        suggestions=tuple(suggestions),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Check password strength locally.")
    parser.parse_args()

    password = getpass.getpass("Password (input hidden): ")
    if not password:
        print("No password entered.")
        return

    assessment = analyze_password(password)
    print(f"Estimated entropy: {assessment.entropy_bits:.1f} bits")
    print(f"Strength: {assessment.label}")
    print("Policy checks:")
    for requirement, passed in assessment.policy_checks:
        status = "PASS" if passed else "FAIL"
        print(f"  [{status}] {requirement}")
    dictionary_status = "MATCH" if assessment.dictionary_match else "no match"
    print(f"Local dictionary check: {dictionary_status}")
    print("Suggestions:")
    for suggestion in assessment.suggestions:
        print(f"- {suggestion}")


if __name__ == "__main__":
    main()