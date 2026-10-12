# Password Strength vs. Real Attacks

CIS256 Honors Project, Fall 2026, Ryan Anderson
Instructor: Professor McClellan

## Research question

How accurately do common password strength measures, such as entropy scores and "must include a number and symbol" rules, predict how quickly a password can actually be cracked?

## What this project does

1. **Builds a test set** of passwords using four strategies: random characters (8, 12, and 16 long), random-word passphrases, rule-following passwords (like `Summer2026!`), and human-style passwords (like `dragon123`).
2. **Scores each password** the way common strength meters do, using entropy and character rules.
3. **Attacks the same passwords** with a dictionary attack, a rule-based attack, and brute-force time estimates. *(in progress)*
4. **Compares** each password's predicted strength to how it actually held up. *(in progress)*

## Files

| File | Purpose |
|---|---|
| `generate_passwords.py` | Creates the four groups of test passwords, scores them, saves `test_passwords.csv` |
| `test_passwords.csv` | Output: every password with its length, entropy, meter score, and label |

## How to run

Requires Python 3 (no extra packages yet).

```
python generate_passwords.py
```

## Progress log

- **Oct. 13** — Project outline and methodology written. Test-set generator and strength scoring working.
