"""
analyzer.py – Password strength scoring engine
SecureGuard Password Strength Analyzer

Scoring breakdown (total 0–10):
  Length     : 0–3 pts
  Complexity : 0–3 pts (char-type diversity)
  Uniqueness : 0–2 pts (char diversity + no heavy repeats)
  Entropy    : 0–2 pts (Shannon entropy)
"""

import math
from collections import Counter

# ── Common passwords blocklist ──
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "password1", "admin",
    "letmein", "welcome", "monkey", "dragon", "master", "iloveyou", "sunshine",
    "princess", "football", "shadow", "superman", "michael", "jessica",
    "password123", "1234567890", "qwerty123", "test1234", "pass1234",
    "admin123", "login123", "passw0rd", "p@ssword", "p@ssw0rd",
    "trustno1", "hello", "hello123", "changeme", "qazwsx", "baseball",
    "starwars", "solo", "access", "batman", "service", "computer",
}

# ── Grade thresholds ──
GRADES = [
    (9.5, "Very Strong", "vstrong"),
    (8.0, "Strong",      "strong"),
    (6.0, "Good",        "good"),
    (4.0, "Fair",        "fair"),
    (0.0, "Weak",        "weak"),
]


def grade_from_score(score: float) -> dict:
    for threshold, label, cls in GRADES:
        if score >= threshold:
            return {"label": label, "cls": cls}
    return {"label": "Weak", "cls": "weak"}


def shannon_entropy(password: str) -> float:
    """Compute Shannon entropy (bits per character)."""
    if not password:
        return 0.0
    freq = Counter(password)
    length = len(password)
    entropy = -sum((c / length) * math.log2(c / length) for c in freq.values())
    return round(entropy, 4)


def analyze(password: str) -> dict:
    """
    Analyze a password and return a full scoring breakdown.

    Returns:
        dict with keys: score, grade, grade_cls, length, entropy,
                        has_upper, has_lower, has_number, has_special,
                        no_repeat, is_common,
                        score_length, score_complexity, score_uniqueness, score_entropy
    """
    length  = len(password)
    freq    = Counter(password)

    has_upper   = any(c.isupper()          for c in password)
    has_lower   = any(c.islower()          for c in password)
    has_number  = any(c.isdigit()          for c in password)
    has_special = any(not c.isalnum()      for c in password)
    is_common   = password.lower() in COMMON_PASSWORDS

    # No heavy repetition: no single char accounts for >40% of length
    max_freq = max(freq.values(), default=0)
    no_repeat = length > 0 and (max_freq / length) <= 0.40

    # ── 1. LENGTH SCORE (0–3) ──
    if length >= 20:      length_score = 3.0
    elif length >= 16:    length_score = 2.7
    elif length >= 12:    length_score = 2.2
    elif length >= 8:     length_score = 1.5
    elif length >= 6:     length_score = 0.7
    elif length >= 1:     length_score = 0.3
    else:                 length_score = 0.0

    # ── 2. COMPLEXITY SCORE (0–3) ──
    complex_score = 0.0
    if has_lower:   complex_score += 0.6
    if has_upper:   complex_score += 0.8
    if has_number:  complex_score += 0.7
    if has_special: complex_score += 0.9

    # ── 3. UNIQUENESS SCORE (0–2) ──
    unique_chars = len(freq)
    unique_score = 0.0
    if length > 0:
        diversity    = unique_chars / length
        unique_score = diversity * 1.2
        if no_repeat:
            unique_score += 0.5
        if is_common:
            unique_score -= 1.5
    unique_score = max(0.0, min(2.0, unique_score))

    # ── 4. ENTROPY SCORE (0–2) ──
    entropy      = shannon_entropy(password)
    entropy_score = min(2.0, (entropy / 4.0) * 2.0)

    # ── TOTAL ──
    total = length_score + complex_score + unique_score + entropy_score
    if is_common:
        total = min(total, 2.0)          # hard cap for common passwords
    total = max(1.0, min(10.0, round(total, 1)))

    grade = grade_from_score(total)

    return {
        "password":          password,
        "score":             total,
        "grade":             grade["label"],
        "grade_cls":         grade["cls"],
        "length":            length,
        "entropy":           entropy,
        "has_upper":         has_upper,
        "has_lower":         has_lower,
        "has_number":        has_number,
        "has_special":       has_special,
        "no_repeat":         no_repeat,
        "is_common":         is_common,
        # sub-scores as percentages (for UI breakdown bars)
        "score_length":      round((length_score  / 3.0) * 100),
        "score_complexity":  round((complex_score / 3.0) * 100),
        "score_uniqueness":  round((unique_score  / 2.0) * 100),
        "score_entropy":     round((entropy_score / 2.0) * 100),
    }
