"""
pattern_meter.py
Honors Project - Password Strength vs. Real Attacks
CIS256, Fall 2026

Step 3 of the project: a smarter, pattern-aware meter.

The first meter (in generate_passwords.py) only rewards character variety and
length. It rates predictable passwords like "Dragon1%" as Very Strong even
though they fall fast. This script adds a second meter that also PENALIZES
predictable patterns, the way Professor McClellan suggested:
  - the "word + number + symbol" template (Summer2026!, Password123!)
  - common words dressed up with leetspeak (p@ssw0rd)

It reads the attack results, rates every password a second way, and compares
the two meters to see which one matches the real crack results better.
Output is saved to pattern_results.csv.

Research question:
How accurately do entropy-based and character-composition-based password
strength assessments predict a password's resistance to guessing attacks?
"""

import csv
import re

# ------------------------------------------------------------
# Settings
# ------------------------------------------------------------
INPUT_FILE = "attack_results.csv"       # made by attack_passwords.py
OUTPUT_FILE = "pattern_results.csv"     # this script's results
WORDLIST_FILE = "common_passwords.txt"  # the common-password list

STRONG_LABELS = ("Strong", "Very Strong")

# Common leetspeak swaps, used to turn "p@ssw0rd" back into "password".
LEET_SWAPS = {"@": "a", "0": "o", "3": "e", "1": "i", "4": "a",
              "5": "s", "7": "t", "$": "s"}


# ------------------------------------------------------------
# Loading the common-password list
# ------------------------------------------------------------
def load_common_words():
    """Return the common passwords as a lowercase set for fast lookups."""
    with open(WORDLIST_FILE, "r", encoding="utf-8", errors="ignore") as file:
        return set(line.strip().lower() for line in file if line.strip())


# ------------------------------------------------------------
# Spotting predictable patterns
# ------------------------------------------------------------
def unleet(text):
    """Undo common leetspeak swaps so p@ssw0rd becomes password."""
    for symbol, letter in LEET_SWAPS.items():
        text = text.replace(symbol, letter)
    return text


def base_word(password):
    """Pull out the leading run of letters (Dragon1% -> dragon)."""
    match = re.match(r"^[A-Za-z]+", password)
    return match.group(0).lower() if match else ""


def leet_base_word(password):
    """Base word after undoing leetspeak, for cases like p@ssw0rd."""
    match = re.match(r"^[A-Za-z]+", unleet(password))
    return match.group(0).lower() if match else ""


def looks_like_template(password):
    """True if the password is letters, then numbers, then optional symbols
    (Summer2026!, dragon123, Dragon1%)."""
    return bool(re.match(r"^[A-Za-z]+[0-9]+[^A-Za-z0-9]*$", password))


def is_predictable(password, common_words):
    """
    True if the password follows an easy, guessable pattern:
      1. it is itself a known common password,
      2. it is a common word plus numbers/symbols on the end, or
      3. it is a common word hidden with leetspeak.
    """
    if password.lower() in common_words:
        return True

    word = base_word(password)
    if looks_like_template(password) and len(word) >= 3 and word in common_words:
        return True

    leet_word = leet_base_word(password)
    if unleet(password) != password and len(leet_word) >= 3 and leet_word in common_words:
        return True

    return False


def pattern_label(password, composition_label, common_words):
    """
    The pattern-aware rating. If the password follows a predictable pattern it
    is rated Weak no matter what characters it uses. Otherwise it keeps the
    original composition rating.
    """
    if is_predictable(password, common_words):
        return "Weak"
    return composition_label


# ------------------------------------------------------------
# Judging each meter against the real results
# ------------------------------------------------------------
def is_overrated(label, cracked):
    """Overrated = rated Strong/Very Strong but cracked anyway."""
    return label in STRONG_LABELS and cracked == "yes"


def is_accurate(label, cracked):
    """
    Accurate = the rating matched reality: Strong/Very Strong and it survived,
    or Weak/Fair and it got cracked.
    """
    strong = label in STRONG_LABELS
    survived = cracked == "no"
    return strong == survived


# ------------------------------------------------------------
# Running the comparison
# ------------------------------------------------------------
def run():
    """Rate every password a second way and compare the two meters."""
    common_words = load_common_words()
    print(f"Loaded {len(common_words):,} common words from {WORDLIST_FILE}.\n")

    results = []
    with open(INPUT_FILE, "r", newline="") as file:
        reader = csv.DictReader(file)
        for row in reader:
            password = row["password"]
            composition = row["meter_label"]
            cracked = row["cracked"]
            pattern = pattern_label(password, composition, common_words)

            results.append({
                "group": row["group"],
                "password": password,
                "entropy_bits": row["entropy_bits"],
                "composition_label": composition,
                "pattern_label": pattern,
                "cracked": cracked,
                "composition_overrated": "yes" if is_overrated(composition, cracked) else "no",
                "pattern_overrated": "yes" if is_overrated(pattern, cracked) else "no",
                "composition_accurate": "yes" if is_accurate(composition, cracked) else "no",
                "pattern_accurate": "yes" if is_accurate(pattern, cracked) else "no",
            })
    return results


def save_results(results, filename):
    """Write the comparison to a CSV file."""
    columns = ["group", "password", "entropy_bits", "composition_label",
               "pattern_label", "cracked", "composition_overrated",
               "pattern_overrated", "composition_accurate", "pattern_accurate"]
    with open(filename, "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=columns)
        writer.writeheader()
        writer.writerows(results)


def print_summary(results):
    """Show how the two meters compare on overrated count and accuracy."""
    groups = {}
    for row in results:
        groups.setdefault(row["group"], []).append(row)

    print(f"{'Group':<16}{'Overrated (comp)':>18}{'Overrated (pattern)':>21}"
          f"{'Accuracy (comp)':>18}{'Accuracy (pattern)':>20}")
    print("-" * 93)
    for group, rows in groups.items():
        total = len(rows)
        comp_over = sum(1 for r in rows if r["composition_overrated"] == "yes")
        pat_over = sum(1 for r in rows if r["pattern_overrated"] == "yes")
        comp_acc = sum(1 for r in rows if r["composition_accurate"] == "yes")
        pat_acc = sum(1 for r in rows if r["pattern_accurate"] == "yes")
        print(f"{group:<16}{comp_over:>18}{pat_over:>21}"
              f"{comp_acc / total * 100:>17.0f}%{pat_acc / total * 100:>19.0f}%")

    print("-" * 93)
    total = len(results)
    comp_over = sum(1 for r in results if r["composition_overrated"] == "yes")
    pat_over = sum(1 for r in results if r["pattern_overrated"] == "yes")
    comp_acc = sum(1 for r in results if r["composition_accurate"] == "yes")
    pat_acc = sum(1 for r in results if r["pattern_accurate"] == "yes")
    print(f"Overrated passwords:  composition meter = {comp_over}, "
          f"pattern-aware meter = {pat_over}")
    print(f"Overall accuracy:     composition meter = {comp_acc / total * 100:.0f}%, "
          f"pattern-aware meter = {pat_acc / total * 100:.0f}%")


def main():
    results = run()
    save_results(results, OUTPUT_FILE)
    print(f"Saved {len(results)} results to {OUTPUT_FILE}.\n")
    print_summary(results)


if __name__ == "__main__":
    main()
