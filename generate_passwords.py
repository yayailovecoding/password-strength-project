"""
generate_passwords.py
Honors Project - Password Strength vs. Real Attacks
CIS256, Fall 2026

Step 1 of the project: build the test set.

This script creates four groups of test passwords and scores each one
the way common password strength meters do (entropy + character rules).
The results are saved to test_passwords.csv so the attack scripts
(coming next) can try to crack the same passwords.

Research question:
How accurately do common password strength measures predict how quickly
a password can actually be cracked?
"""

import csv
import math
import secrets
import string

# ------------------------------------------------------------
# Settings
# ------------------------------------------------------------
PASSWORDS_PER_GROUP = 25
OUTPUT_FILE = "test_passwords.csv"

# Words people commonly use as a base for their passwords.
# (Later: replace with words pulled from a real leaked-password list.)
COMMON_BASE_WORDS = [
    "password", "dragon", "monkey", "sunshine", "princess", "football",
    "baseball", "shadow", "master", "summer", "winter", "spring", "autumn",
    "soccer", "hunter", "ranger", "tigger", "cookie", "pepper", "ginger",
    "jordan", "michael", "jessica", "ashley", "charlie", "buster", "maggie",
    "welcome", "freedom", "purple", "orange", "chicken", "letmein", "love",
    "flower", "angel", "family", "phoenix", "arizona", "batman",
]

# Words used to build random passphrases.
# (Later: replace with the EFF Diceware word list for a bigger pool.)
PASSPHRASE_WORDS = [
    "apple", "river", "candle", "planet", "forest", "rocket", "pillow",
    "garden", "silver", "thunder", "basket", "castle", "pencil", "tiger",
    "window", "marble", "harbor", "violin", "cactus", "meadow", "anchor",
    "blanket", "canyon", "dolphin", "engine", "falcon", "glacier", "hammer",
    "island", "jacket", "kettle", "ladder", "magnet", "napkin", "orbit",
    "parrot", "quartz", "ribbon", "saddle", "tunnel", "umbrella", "valley",
    "walnut", "yogurt", "zipper", "bridge", "copper", "desert", "feather",
    "guitar", "honey", "igloo", "jungle", "koala", "lemon", "mirror",
    "needle", "oyster", "pepper", "quiver", "rabbit", "spoon", "tractor",
]

SYMBOLS = "!@#$%^&*"


# ------------------------------------------------------------
# Password generators (one function per strategy)
# ------------------------------------------------------------
def make_random_password(length):
    """Random characters from letters, digits, and symbols."""
    pool = string.ascii_letters + string.digits + string.punctuation
    return "".join(secrets.choice(pool) for _ in range(length))


def make_passphrase(word_count=4):
    """Random words joined with dashes, like 'river-candle-tiger-orbit'."""
    words = [secrets.choice(PASSPHRASE_WORDS) for _ in range(word_count)]
    return "-".join(words)


def make_rule_following_password():
    """
    Meets typical website rules (capital, number, symbol) the way
    people usually satisfy them: Capitalized word + year/number + symbol.
    Example: 'Summer2026!'
    """
    word = secrets.choice(COMMON_BASE_WORDS).capitalize()
    number = secrets.choice(["1", "12", "123", "2024", "2025", "2026", "99", "01"])
    symbol = secrets.choice(SYMBOLS)
    return word + number + symbol


def make_human_style_password():
    """Simple patterns people actually use, like 'dragon123'."""
    word = secrets.choice(COMMON_BASE_WORDS)
    ending = secrets.choice(["", "1", "12", "123", "1234", "69", "007", "2000"])
    return word + ending


# ------------------------------------------------------------
# Strength scoring (how strength meters usually judge passwords)
# ------------------------------------------------------------
def character_pool_size(password):
    """Count how many possible characters the password *could* use."""
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(not c.isalnum() for c in password):
        pool += 32
    return pool


def entropy_bits(password):
    """Entropy = length x log2(pool size). Higher looks 'stronger'."""
    pool = character_pool_size(password)
    if pool == 0:
        return 0.0
    return round(len(password) * math.log2(pool), 1)


def meter_score(password):
    """
    A simple rule-based meter like many websites use.
    One point for each rule passed (0 to 6).
    """
    score = 0
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if any(c.islower() for c in password):
        score += 1
    if any(c.isupper() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(not c.isalnum() for c in password):
        score += 1
    return score


def meter_label(score):
    """Turn the 0-6 score into the label a website would show."""
    if score <= 2:
        return "Weak"
    elif score <= 3:
        return "Fair"
    elif score <= 4:
        return "Strong"
    else:
        return "Very Strong"


# ------------------------------------------------------------
# Build the test set
# ------------------------------------------------------------
def build_test_set():
    """Create every group of passwords and return them as a list of (group, password)."""
    test_set = []

    # Random characters at three lengths
    for length in (8, 12, 16):
        for _ in range(PASSWORDS_PER_GROUP):
            test_set.append((f"random_{length}", make_random_password(length)))

    for _ in range(PASSWORDS_PER_GROUP):
        test_set.append(("passphrase", make_passphrase()))

    for _ in range(PASSWORDS_PER_GROUP):
        test_set.append(("rule_following", make_rule_following_password()))

    for _ in range(PASSWORDS_PER_GROUP):
        test_set.append(("human_style", make_human_style_password()))

    return test_set


def save_results(test_set, filename):
    """Score every password and write the results to a CSV file."""
    with open(filename, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["group", "password", "length", "entropy_bits",
                         "meter_score", "meter_label"])
        for group, password in test_set:
            score = meter_score(password)
            writer.writerow([group, password, len(password),
                             entropy_bits(password), score, meter_label(score)])


def print_summary(test_set):
    """Show the average entropy and most common meter label for each group."""
    groups = {}
    for group, password in test_set:
        groups.setdefault(group, []).append(password)

    print(f"{'Group':<16}{'Avg length':>11}{'Avg entropy':>13}   Most common label")
    print("-" * 62)
    for group, passwords in groups.items():
        avg_len = sum(len(p) for p in passwords) / len(passwords)
        avg_ent = sum(entropy_bits(p) for p in passwords) / len(passwords)
        labels = [meter_label(meter_score(p)) for p in passwords]
        common = max(set(labels), key=labels.count)
        print(f"{group:<16}{avg_len:>11.1f}{avg_ent:>13.1f}   {common}")


def main():
    test_set = build_test_set()
    save_results(test_set, OUTPUT_FILE)
    print(f"Created {len(test_set)} test passwords and saved them to {OUTPUT_FILE}\n")
    print_summary(test_set)


if __name__ == "__main__":
    main()
