# Contributing to injectguard

Thanks for your interest in improving injectguard!

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/kriskimmerle/injectguard.git
   cd injectguard
   ```

2. No dependencies needed - injectguard is pure Python stdlib.

3. Run tests:
   ```bash
   python -m unittest test_injectguard -v
   ```

## Code Style

- Follow PEP 8 guidelines
- Maximum line length: 100 characters
- Use type hints from `__future__ import annotations`
- Document all rules with docstrings

## Adding New Detection Rules

Each rule follows this pattern:

```python
@rule("PI999", Severity.HIGH, "Rule title", "Description")
def check_new_pattern(text: str, findings: list[Finding]):
    patterns = [
        (r"regex_pattern", "Detection message"),
    ]
    for pattern, msg in patterns:
        for m in re.finditer(pattern, text):
            add_finding(findings, text, "PI999", Severity.HIGH,
                       "Rule title", msg, match_obj=m)
```

### Rule ID Convention

- PI001-PI099: Instruction manipulation
- PI100-PI199: Data exfiltration
- PI200-PI299: Jailbreaking
- PI300-PI399: Encoding/obfuscation
- PI400-PI499: Context manipulation
- PI500+: Reserved for future categories

### Rule Guidelines

- Use `(?i)` for case-insensitive matching
- Avoid overly broad patterns (minimize false positives)
- Include word boundaries (`\b`) where appropriate
- Test against known injection examples
- Document why the pattern is dangerous

## Testing

- Add tests for each new rule in `test_injectguard.py`
- Test both positive cases (catches injection) and negative cases (no false positives)
- Run full test suite before submitting PR

Example test:

```python
def test_my_new_rule(self):
    """Test detection of X pattern"""
    text = "example injection text"
    result = injectguard.scan(text)
    self.assertTrue(any(f.rule_id == "PI999" for f in result.findings))
```

## Submitting Changes

1. Fork the repository
2. Create a feature branch: `git checkout -b add-rule-pi999`
3. Make your changes
4. Add tests
5. Run tests: `python -m unittest test_injectguard`
6. Run linter: `flake8 injectguard.py`
7. Commit with clear message
8. Push to your fork
9. Open a pull request

## Pull Request Guidelines

- One rule or feature per PR
- Include test cases
- Update README if adding major features
- Ensure CI passes
- Respond to review feedback

## Reporting False Positives

If injectguard flags legitimate content:

1. Open an issue with:
   - The text that triggered false positive
   - Rule ID that fired
   - Why it's a false positive
   - Suggested fix (if any)

2. We'll review and adjust the pattern to be more specific

## Reporting Bypasses

If you find an injection that injectguard misses:

1. Open an issue (do NOT include exploits publicly if sensitive)
2. Describe the injection technique
3. We'll create a new rule or update existing ones

## Questions?

Open an issue with the `question` label.
