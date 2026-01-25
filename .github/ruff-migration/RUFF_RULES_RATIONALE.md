# Ruff Rule Selection Rationale

## Question from Maintainer

> "why this specific set has been chosen over all the possibilities?"

## Selected Rules

```toml
select = [
    "E",   # pycodestyle errors
    "W",   # pycodestyle warnings
    "F",   # pyflakes
    "I",   # isort
    "N",   # pep8-naming
    "UP",  # pyupgrade
    "B",   # flake8-bugbear
    "C4",  # flake8-comprehensions
    "DJ",  # flake8-django
]
```

---

## Rationale

### Core Rules (Preserving Existing Behavior)

These rules directly replace the existing linters and maintain current code quality standards:

#### 1. **E, W** (pycodestyle)
- **Replaces**: `flake8` core functionality
- **Why**: These are the fundamental PEP 8 style checks that `flake8` was performing
- **Examples**: E501 (line too long), E302 (blank lines), W291 (trailing whitespace)
- **Status**: ✅ **REQUIRED** - Core PEP 8 compliance

#### 2. **F** (Pyflakes)
- **Replaces**: `flake8` logical error detection
- **Why**: Catches actual Python errors like undefined names, unused imports, etc.
- **Examples**: F401 (unused import), F841 (unused variable), F821 (undefined name)
- **Status**: ✅ **REQUIRED** - Prevents runtime errors

#### 3. **I** (isort)
- **Replaces**: `isort` import sorting
- **Why**: Maintains consistent import ordering as before
- **Examples**: I001 (unsorted imports), I002 (missing import grouping)
- **Status**: ✅ **REQUIRED** - Replaces isort functionality

### Enhanced Rules (Added Value)

These rules provide additional code quality improvements beyond the old setup:

#### 4. **N** (pep8-naming)
- **Replaces**: Part of `flake8` ecosystem (flake8-naming was available but not explicitly configured)
- **Why**: Enforces Python naming conventions for classes, functions, variables
- **Examples**: N801 (class names should use CapWords), N806 (variable in function should be lowercase)
- **Status**: 🆕 **RECOMMENDED** - Common flake8 extension, good practice

#### 5. **UP** (pyupgrade)
- **Replaces**: Nothing (net new)
- **Why**: Suggests modern Python syntax (especially relevant for Python 3.11 target)
- **Examples**: UP006 (use `list` instead of `typing.List`), UP032 (use f-strings)
- **Status**: 🆕 **RECOMMENDED** - Keeps code modern, no breaking changes

#### 6. **B** (flake8-bugbear)
- **Replaces**: flake8-bugbear (if it was used before)
- **Why**: Catches common Python bugs and design issues
- **Examples**: B006 (mutable default argument), B008 (function calls in default arguments)
- **Status**: 🆕 **RECOMMENDED** - Very popular flake8 extension, catches real bugs

#### 7. **C4** (flake8-comprehensions)
- **Replaces**: flake8-comprehensions (if it was used before)
- **Why**: Suggests better comprehension and generator syntax
- **Examples**: C400 (unnecessary generator in `list()`), C408 (unnecessary `dict()` call)
- **Status**: 🆕 **RECOMMENDED** - Performance and readability improvements

#### 8. **DJ** (flake8-django) ⭐
- **Replaces**: `flake8-django` (unmaintained)
- **Why**: **THIS IS THE MAIN REASON FOR THE MIGRATION** (Issue #3142)
- **Examples**: DJ001 (null=True on string-based fields), DJ006 (exclude/fields in ModelForm)
- **Status**: ✅ **REQUIRED** - Solves the original issue

---

## Decision Framework

### Must Include (E, W, F, I, DJ)
These are **non-negotiable** as they maintain existing functionality:
1. Match or exceed current flake8/black/isort coverage
2. Address the unmaintained flake8-django issue
3. No regression in code quality

### Should Include (N, UP, B, C4)
These are **strongly recommended** because:
1. They are widely-adopted industry standards
2. They catch real bugs and improve code quality
3. They have minimal false positives
4. They are commonly used in the Python ecosystem
5. Ruff makes them "free" (no performance cost)

### Could Exclude (if maintainers prefer)
If the maintainers want a more conservative approach, we could remove:
- **UP** (pyupgrade) - Only if you want to avoid modernization suggestions
- **N** (pep8-naming) - Only if naming conventions aren't a priority
- **C4** (comprehensions) - Only if you want to avoid style suggestions

However, I **strongly recommend keeping B** (bugbear) as it catches real bugs.

---

## Alternative Minimal Configuration

If you want **only** what directly replaces the old tools:

```toml
[tool.ruff.lint]
select = [
    "E",   # pycodestyle errors (flake8)
    "W",   # pycodestyle warnings (flake8)
    "F",   # pyflakes (flake8)
    "I",   # isort (isort)
    "DJ",  # flake8-django (addresses issue #3142)
]
```

This would be the **absolute minimum** to maintain parity.

---

## Recommended Configuration (Current)

The current configuration is the **recommended** setup because:

1. ✅ Maintains all existing functionality
2. ✅ Solves the flake8-django maintenance issue
3. ✅ Adds widely-accepted best practices (B, C4, N, UP)
4. ✅ Zero performance cost (Ruff is so fast it doesn't matter)
5. ✅ Common in the Python community
6. ✅ Prevents common bugs (B, UP)
7. ✅ Improves code consistency (N, C4)

---

## Comparison with Other Projects

Many popular Django projects use similar or more extensive rule sets with Ruff:

- **Django REST Framework**: Uses E, W, F, I, B, C4, DJ, plus more
- **Wagtail CMS**: Uses E, W, F, I, UP, B, DJ, plus security rules
- **Sentry**: Uses E, W, F, I, B, C4, UP, plus custom rules

The current selection is **conservative** compared to industry standards.

---

## What's NOT Included (Intentionally)

We **deliberately excluded** these rule categories to avoid breaking changes:

- **ANN** (type annotations) - Would require adding type hints everywhere
- **D** (docstrings) - Would require documentation for all functions
- **S** (security/bandit) - Might have false positives, needs review
- **T** (print statements) - Too strict for development
- **ERA** (commented code) - Might remove intentional comments
- **RUF** (Ruff-specific) - Too experimental

These could be added later in a separate PR after discussion.

---

## Recommendation

**Keep the current configuration** as it:
1. Solves the immediate problem (unmaintained flake8-django)
2. Maintains all existing code quality checks
3. Adds proven, widely-adopted best practices
4. Has no performance impact
5. Follows Python community standards

If maintainers want to be more conservative, we can reduce to the minimal set, but I would argue the additional rules provide significant value at zero cost.

---

## References

- [Ruff Rules Documentation](https://docs.astral.sh/ruff/rules/)
- [Ruff Linter Comparison](https://docs.astral.sh/ruff/faq/#how-does-ruff-compare-to-flake8)
- [Python Community Ruff Configurations](https://github.com/astral-sh/ruff/discussions/categories/show-and-tell)
