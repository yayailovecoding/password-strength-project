# Password Strength vs. Real Attacks

CIS256 Honors Project, Fall 2026, Ryan Anderson
Instructor: Professor McClellan

## Research question

How accurately do entropy-based and character-composition-based password strength assessments predict a password's resistance to guessing attacks?

## What this project does

1. **Builds a test set** of passwords using four strategies: random characters (8, 12, and 16 long), random-word passphrases, rule-following passwords (like `Summer2026!`), and human-style passwords (like `dragon123`).
2. **Scores each password** the way common strength meters do, using entropy and character rules.
3. **Attacks the same passwords** with a dictionary attack, a rule-based attack, and brute-force time estimates.
4. **Compares** each password's predicted strength to how it actually held up.
5. **Rates them a second way** with a pattern-aware meter that penalizes predictable patterns (the word+number+symbol template and leetspeak), then checks which meter matches the real results better.

## Files

| File | Purpose |
|---|---|
| `generate_passwords.py` | Creates the four groups of test passwords, scores them, saves `test_passwords.csv` |
| `test_passwords.csv` | Output: every password with its length, entropy, meter score, and label |
| `attack_passwords.py` | Attacks the passwords (dictionary, rule-based, brute-force estimate), saves `attack_results.csv` |
| `common_passwords.txt` | The 10,000 most common passwords (from SecLists), saved locally so the attack runs offline |
| `attack_results.csv` | Output: every password with whether it was cracked, how, guesses needed, and whether it was overrated |
| `pattern_meter.py` | Rates every password a second way with a pattern-aware meter, compares it to the composition meter, saves `pattern_results.csv` |
| `pattern_results.csv` | Output: each password's composition label vs. pattern-aware label, plus whether each meter was overrated and accurate |

## How to run

Requires Python 3 (no extra packages yet).

```
python generate_passwords.py
python attack_passwords.py
python pattern_meter.py
```

The first run of `attack_passwords.py` downloads the common-password list and saves it as `common_passwords.txt`; after that it runs offline.

## Progress log

- **Oct. 13:** Project outline and methodology written. Test-set generator and strength scoring working.
- **Oct. 27:** Updated the research question per Professor McClellan's feedback and wrote `attack_passwords.py`, which runs the dictionary attack (SecLists 10k list), the rule-based attack (capitalization, leetspeak, and numbers/symbols on the end), and the brute-force time estimate. The preliminary results back up the early hunch: all 75 random passwords and all 25 passphrases survived, but all 25 rule-following passwords (like `Dragon1%`) got cracked even though the meter called them Strong or Very Strong. That left 26 passwords overrated (rated Strong/Very Strong but cracked), 25 of them rule-following. So the main measure, the share of Strong/Very Strong passwords cracked anyway, came out to 100% for the rule-following group and 0% for the random and passphrase groups.
- **Nov. 10:** Added a pattern-aware meter (`pattern_meter.py`) per Professor McClellan's feedback. It penalizes predictable patterns the composition meter ignores: the word+number+symbol template (like `Summer2026!`) and common words hidden with leetspeak (like `p@ssw0rd`). Comparing the two meters against the attack results, the original composition meter overrated 26 passwords and was 82% accurate, while the pattern-aware meter overrated 0 and was 99% accurate. The gain comes almost entirely from correctly downgrading the rule-following group from Very Strong to Weak (0% to 100% accurate). The one password neither meter gets right is a short random one the composition meter under-rated, which is a different kind of error than the overrating this project focuses on. Also started the rough draft of the written report.
