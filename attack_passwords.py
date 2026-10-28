"""
attack_passwords.py
Honors Project - Password Strength vs. Real Attacks
CIS256, Fall 2026

Step 2 of the project: attack the test set.

This script reads the passwords from generate_passwords.py and tries to crack
them the way a real attacker would, using a list of common passwords. Then it
checks whether the strength meter's rating actually held up.

The three attacks:
  1. Dictionary attack: is the password already a known common password?
  2. Rule-based attack: common words with simple tricks (Dragon1%, p@ss123).
  3. Brute-force estimate: how long to try every combination (just an estimate).

Results are saved to attack_results.csv.

Research question:
How accurately do entropy-based and character-composition-based password
strength assessments predict a password's resistance to guessing attacks?
"""

import csv
import math
import os
import urllib.request

# ------------------------------------------------------------
# Settings
# ------------------------------------------------------------
INPUT_FILE = "test_passwords.csv"       # made by generate_passwords.py
OUTPUT_FILE = "attack_results.csv"      # this script's results
WORDLIST_FILE = "common_passwords.txt"  # saved locally so we can run offline

# SecLists' list of the 10,000 most common passwords.
WORDLIST_URL = ("https://raw.githubusercontent.com/danielmiessler/SecLists/"
                "master/Passwords/Common-Credentials/10k-most-common.txt")

# For the rule-based attack we only add tricks to the most common words
# (the top of the list). This keeps the program fast and is realistic:
# an attacker tries the most common words first.
RULE_WORDLIST_SIZE = 2000

# Numbers people commonly tack onto the end of a password. This set covers
# the endings our own generator uses (years, 123, 69, 007, etc.).
COMMON_NUMBERS = ["1", "12", "123", "1234", "2000", "2024", "2025", "2026",
                  "99", "01", "69", "007"]

# Symbols people commonly tack onto the end.
COMMON_SYMBOLS = ["!", "@", "#", "$", "%", "^", "&", "*"]

# Assumed attacker speed for the brute-force ESTIMATE only: 10 billion
# guesses per second. This is a realistic rate for a modern GPU cracking a
# fast/unsalted hash offline. It is just used for the time math below.
GUESSES_PER_SECOND = 10_000_000_000


# ------------------------------------------------------------
# Getting the common-password word list
# ------------------------------------------------------------
def load_wordlist():
    """
    Return the list of common passwords. The first run downloads the list and
    saves it to common_passwords.txt; after that it reads the saved file, so
    the program works offline.
    """
    if not os.path.exists(WORDLIST_FILE):
        print(f"Downloading common-password list to {WORDLIST_FILE} ...")
        urllib.request.urlretrieve(WORDLIST_URL, WORDLIST_FILE)
        print("Download complete.\n")

    with open(WORDLIST_FILE, "r", encoding="utf-8", errors="ignore") as file:
        # One password per line; strip the newline off each one.
        return [line.strip() for line in file if line.strip()]


# ------------------------------------------------------------
# The tricks people use to "strengthen" a common word
# ------------------------------------------------------------
def leetspeak(word):
    """Swap letters for look-alike symbols/numbers: a->@, o->0, e->3."""
    return word.replace("a", "@").replace("o", "0").replace("e", "3")


def word_variations(word):
    """
    Build the base forms of a word an attacker would try: the word itself,
    Capitalized, and both of those in leetspeak. Duplicates are removed.
    """
    forms = [word, word.capitalize(), leetspeak(word), leetspeak(word.capitalize())]
    unique = []
    for form in forms:
        if form not in unique:
            unique.append(form)
    return unique


def word_guesses(word):
    """
    For one word, yield every rule-based guess in order: each base form, then
    that form with a number, a symbol, or a number+symbol on the end
    (Dragon, Dragon1, Dragon!, Dragon1!, ...).
    """
    for base in word_variations(word):
        yield base                                  # just the word
        for number in COMMON_NUMBERS:
            yield base + number                     # word + number
        for symbol in COMMON_SYMBOLS:
            yield base + symbol                     # word + symbol
        for number in COMMON_NUMBERS:
            for symbol in COMMON_SYMBOLS:
                yield base + number + symbol        # word + number + symbol


# ------------------------------------------------------------
# Building the full guess list once (so each attack is fast)
# ------------------------------------------------------------
def build_guess_index(wordlist):
    """
    Walk the attacker's guesses in order and record the guess number where each
    one first shows up. Returns two dictionaries:

      dict_guesses : {password: guess number} for the plain dictionary attack
      rule_guesses : {password: guess number} for the rule-based attack

    Looking a password up in these tells us right away whether it gets cracked
    and how many guesses it took.
    """
    dict_guesses = {}
    count = 0
    # Attack 1: try every word in the list exactly as it is.
    for word in wordlist:
        count += 1
        if word not in dict_guesses:
            dict_guesses[word] = count

    rule_guesses = {}
    # Attack 2: keep counting, now adding tricks to the most common words.
    for word in wordlist[:RULE_WORDLIST_SIZE]:
        for guess in word_guesses(word):
            count += 1
            if guess not in rule_guesses and guess not in dict_guesses:
                rule_guesses[guess] = count

    return dict_guesses, rule_guesses


def attack_password(password, dict_guesses, rule_guesses):
    """
    Decide whether one password gets cracked.

    Returns (cracked, attack_name, guesses_needed):
      - If it is in the dictionary list  -> ("yes", "dictionary", guess number)
      - Else if a rule-based trick makes it -> ("yes", "rule-based", guess number)
      - Otherwise                          -> ("no", "none", "")
    """
    if password in dict_guesses:
        return "yes", "dictionary", dict_guesses[password]
    if password in rule_guesses:
        return "yes", "rule-based", rule_guesses[password]
    return "no", "none", ""


# ------------------------------------------------------------
# Brute-force time estimate (no real guessing, just math)
# ------------------------------------------------------------
def character_pool_size(password):
    """Count how many different characters the password could be built from."""
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


def human_time(seconds):
    """Turn a number of seconds into a short, readable length of time."""
    if seconds < 1:
        return "< 1 second"
    minute, hour, day, year = 60, 3600, 86400, 86400 * 365
    if seconds < minute:
        return f"{seconds:.0f} seconds"
    if seconds < hour:
        return f"{seconds / minute:.0f} minutes"
    if seconds < day:
        return f"{seconds / hour:.0f} hours"
    if seconds < year:
        return f"{seconds / day:.0f} days"
    years = seconds / year
    if years < 1000:
        return f"{years:,.0f} years"
    return f"{years:.1e} years"   # scientific notation for huge numbers


def brute_force_estimate(password):
    """
    Estimate how long it would take to try every possible combination of the
    password's length and character pool, at GUESSES_PER_SECOND.
    """
    pool = character_pool_size(password)
    if pool == 0:
        return "< 1 second"
    total_combinations = pool ** len(password)
    seconds = total_combinations / GUESSES_PER_SECOND
    return human_time(seconds)


# ------------------------------------------------------------
# Reading the test set and running every attack
# ------------------------------------------------------------
def run_attacks():
    """Attack every password from the CSV and return the results as a list of rows."""
    wordlist = load_wordlist()
    print(f"Loaded {len(wordlist):,} common passwords from {WORDLIST_FILE}.")
    print(f"Building the attacker's guess list (this takes a moment) ...")
    dict_guesses, rule_guesses = build_guess_index(wordlist)
    print(f"Ready. Attacking the passwords in {INPUT_FILE}.\n")

    results = []
    with open(INPUT_FILE, "r", newline="") as file:
        reader = csv.DictReader(file)
        for row in reader:
            group = row["group"]
            password = row["password"]
            entropy = row["entropy_bits"]
            label = row["meter_label"]

            cracked, attack, guesses = attack_password(password, dict_guesses, rule_guesses)
            brute = brute_force_estimate(password)

            # "Overrated" = the meter said Strong/Very Strong, but we cracked it.
            overrated = "yes" if (cracked == "yes" and label in ("Strong", "Very Strong")) else "no"

            results.append({
                "group": group,
                "password": password,
                "entropy_bits": entropy,
                "meter_label": label,
                "cracked": cracked,
                "attack_used": attack,
                "guesses_needed": guesses,
                "brute_force_estimate": brute,
                "overrated": overrated,
            })
    return results


def save_results(results, filename):
    """Write every attack result to a CSV file."""
    columns = ["group", "password", "entropy_bits", "meter_label", "cracked",
               "attack_used", "guesses_needed", "brute_force_estimate", "overrated"]
    with open(filename, "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=columns)
        writer.writeheader()
        writer.writerows(results)


# ------------------------------------------------------------
# Summary table (the main results of the project)
# ------------------------------------------------------------
def print_summary(results):
    """
    Print one row per group with:
      - crack rate (how many were cracked)
      - average entropy
      - most common meter label
      - % of Strong/Very Strong passwords that were cracked anyway (main measure)
    """
    # Group the result rows by their group name.
    groups = {}
    for row in results:
        groups.setdefault(row["group"], []).append(row)

    print(f"{'Group':<16}{'Crack rate':>12}{'Avg entropy':>13}"
          f"{'Common label':>15}{'Strong cracked':>16}")
    print("-" * 72)

    for group, rows in groups.items():
        total = len(rows)
        cracked = sum(1 for r in rows if r["cracked"] == "yes")
        avg_entropy = sum(float(r["entropy_bits"]) for r in rows) / total

        labels = [r["meter_label"] for r in rows]
        common_label = max(set(labels), key=labels.count)

        # Main measure: of the passwords rated Strong/Very Strong, how many
        # were cracked anyway?
        strong = [r for r in rows if r["meter_label"] in ("Strong", "Very Strong")]
        strong_cracked = sum(1 for r in strong if r["cracked"] == "yes")
        if strong:
            strong_pct = f"{strong_cracked}/{len(strong)} ({strong_cracked / len(strong) * 100:.0f}%)"
        else:
            strong_pct = "n/a"

        crack_rate = f"{cracked}/{total} ({cracked / total * 100:.0f}%)"
        print(f"{group:<16}{crack_rate:>12}{avg_entropy:>13.1f}"
              f"{common_label:>15}{strong_pct:>16}")

    # Overall totals across all groups.
    print("-" * 72)
    total = len(results)
    cracked = sum(1 for r in results if r["cracked"] == "yes")
    overrated = sum(1 for r in results if r["overrated"] == "yes")
    print(f"Overall: {cracked}/{total} cracked "
          f"({cracked / total * 100:.0f}%).  "
          f"{overrated} passwords were OVERRATED "
          f"(rated Strong/Very Strong but cracked).")


def main():
    results = run_attacks()
    save_results(results, OUTPUT_FILE)
    print(f"Saved {len(results)} results to {OUTPUT_FILE}.\n")
    print_summary(results)


if __name__ == "__main__":
    main()
