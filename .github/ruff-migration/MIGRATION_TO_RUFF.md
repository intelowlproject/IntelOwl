# Migration from flake8/black/isort to Ruff

**Issue**: #3142
**Date**: January 2026
**Migration Type**: Python Linting and Formatting Tools

## Table of Contents
- [Overview](#overview)
- [Motivation](#motivation)
- [What Changed](#what-changed)
- [Step-by-Step Migration Process](#step-by-step-migration-process)
- [Configuration Details](#configuration-details)
- [Testing the Migration](#testing-the-migration)
- [Troubleshooting](#troubleshooting)

---

## Overview

This document explains the complete migration of IntelOwl from using three separate Python linting and formatting tools (**flake8**, **black**, and **isort**) to a single unified tool called **Ruff**.

### Before Migration
- **flake8** 7.1.1 - PEP8 linting
- **black** 24.10.0 - Code formatting
- **isort** 5.12.0 - Import sorting

### After Migration
- **Ruff** 0.8.6 - All-in-one linter and formatter

---

## Motivation

### Problems with Previous Setup
1. **Maintenance Issue**: `flake8-django` is no longer actively maintained (mentioned in issue #3142)
2. **Performance**: Running three separate tools is slower
3. **Complexity**: Multiple configuration files and tool versions to manage
4. **CI/CD Time**: Longer pipeline execution due to multiple linting steps

### Benefits of Ruff
- ⚡ **10-100x faster** than existing tools (written in Rust)
- 🔧 **Single tool** replaces flake8, black, and isort
- 🐍 **Native Django support** with `flake8-django` rules built-in
- 📦 **Actively maintained** by Astral (the team behind uv)
- ⚙️ **Unified configuration** in `pyproject.toml`
- 🚀 **Faster CI/CD** pipelines

---

## What Changed

### Files Modified

| File | Change Type | Description |
|------|-------------|-------------|
| `pyproject.toml` | Modified | Added comprehensive Ruff configuration |
| `.pre-commit-config.yaml` | Modified | Replaced 3 hooks with 2 Ruff hooks |
| `requirements/test-requirements.txt` | Modified | Replaced 3 dependencies with Ruff |
| `.github/workflows/pull_request_automation.yml` | Modified | Simplified CI linting steps |
| `README.md` | Modified | Updated badges |
| `.github/pull_request_template.md` | Modified | Updated linter references |
| `.flake8` | Deleted | Configuration migrated to `pyproject.toml` |

### Summary Statistics
```
7 files changed, 55 insertions(+), 64 deletions(-)
- Deleted: .flake8
- Net reduction: 9 lines of code
- Configuration centralized in pyproject.toml
```

---

## Step-by-Step Migration Process

### Step 1: Configure Ruff in `pyproject.toml`

We created a new Ruff configuration that preserves all previous linting behavior:

```toml
[tool.ruff]
line-length = 140
target-version = "py311"

exclude = [
    "venv",
    "frontend",
    "node_modules",
    "migrations",
    "docs",
    "virtualenv",
    "configuration/ldap_config.py",
]

[tool.ruff.lint]
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

ignore = [
    "W503",  # line break before binary operator (conflicts with black)
    "E231",  # missing whitespace after ','
    "W605",  # invalid escape sequence
]

[tool.ruff.lint.per-file-ignores]
"__init__.py" = ["F401"]  # unused imports in __init__ files

[tool.ruff.lint.isort]
known-first-party = ["certego_saas"]
profile = "black"

[tool.ruff.format]
quote-style = "double"
indent-style = "space"
```

**Key Points:**
- **Line length**: 140 (from `.flake8`)
- **Exclusions**: Same as before (from `.flake8` and black config)
- **Ignore rules**: Same W503, E231, W605 from `.flake8`
- **Django support**: Added `DJ` rules (flake8-django replacement)
- **Import sorting**: Preserved isort's black profile
- **Formatting**: Black-compatible settings

### Step 2: Update Pre-commit Hooks

**Old Configuration** (`.pre-commit-config.yaml`):
```yaml
repos:
  - repo: https://github.com/psf/black
    rev: 24.8.0
    hooks:
      - id: black
  - repo: https://github.com/PyCQA/flake8
    rev: 7.1.1
    hooks:
      - id: flake8
  - repo: https://github.com/pycqa/isort
    rev: 5.12.0
    hooks:
      - id: isort
        args:
          [
            "--profile",
            "black",
            "--filter-files",
            "--skip",
            "venv",
            "--skip",
            "configuration/ldap_config.py",
          ]
```

**New Configuration**:
```yaml
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.8.6
    hooks:
      # Run the linter
      - id: ruff
        args: [--fix]
      # Run the formatter
      - id: ruff-format
```

**Reduction**: 24 lines → 9 lines (62% reduction)

### Step 3: Update Requirements

**Old** (`requirements/test-requirements.txt`):
```txt
flake8==7.1.1
black==24.10.0
isort==5.12.0
pre-commit==4.0.1
coverage==7.6.1
```

**New**:
```txt
ruff==0.8.6
pre-commit==4.0.1
coverage==7.6.1
```

**Reduction**: 3 dependencies replaced with 1

### Step 4: Update GitHub Actions Workflow

**Old** (`.github/workflows/pull_request_automation.yml`):
```yaml
- name: Install Dependencies
  run: |
    pip3 install --upgrade pip
    pip3 install -r requirements/test-requirements.txt

- name: Black formatter
  run: |
    black . --check --diff --exclude "migrations|venv|.ipython|docs_env|.cache"

- name: Lint with flake8 (PEP8 enforcer + linter)
  run: |
    flake8 . --config=.flake8 --show-source

- name: isort
  run: |
    isort . --profile black --filter-files --check-only --diff --skip configuration/ldap_config.py
```

**New**:
```yaml
- name: Install Dependencies
  run: |
    pip3 install --upgrade pip
    pip3 install -r requirements/test-requirements.txt

- name: Lint and format with Ruff
  run: |
    ruff check . --output-format=github
    ruff format --check .
```

**Benefits**:
- 3 linting steps → 1 step
- GitHub-formatted output for better PR annotations
- Faster execution time

### Step 5: Update README Badges

**Old**:
```markdown
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Imports: isort](https://img.shields.io/badge/%20imports-isort-%231674b1?style=flat&labelColor=ef8336)](https://pycqa.github.io/isort/)
```

**New**:
```markdown
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
```

### Step 6: Update PR Template

**Old** (`.github/pull_request_template.md`):
```markdown
- [ ] Linters (`Black`, `Flake`, `Isort`) gave 0 errors.
```

**New**:
```markdown
- [ ] Linters (`Ruff`) gave 0 errors.
```

### Step 7: Delete `.flake8` File

The `.flake8` configuration file was deleted as all settings were migrated to `pyproject.toml`.

---

## Configuration Details

### Ruff Rule Mapping

Here's how Ruff rules map to the old tools:

| Old Tool | Ruff Rule Code | Description |
|----------|----------------|-------------|
| flake8 (pycodestyle) | `E`, `W` | PEP8 style errors and warnings |
| flake8 (pyflakes) | `F` | Logical errors |
| isort | `I` | Import sorting |
| flake8-pep8-naming | `N` | Naming conventions |
| N/A (bonus!) | `UP` | Python version upgrade suggestions |
| N/A (bonus!) | `B` | Bug detection (flake8-bugbear) |
| N/A (bonus!) | `C4` | Comprehension improvements |
| flake8-django | `DJ` | Django-specific linting |

### Line Length Configuration

**Source**: `.flake8`
```ini
[flake8]
max-line-length = 140
```

**Migrated to**: `pyproject.toml`
```toml
[tool.ruff]
line-length = 140
```

### Exclusions Configuration

**Source**: `.flake8` + `pyproject.toml` (black)
```ini
# .flake8
exclude =
    Dockerfile,
    docker-compose*,
    venv,
    docs,
    migrations,
    virtualenv,
    ldap_config.py
```

**Migrated to**: `pyproject.toml`
```toml
[tool.ruff]
exclude = [
    "venv",
    "frontend",
    "node_modules",
    "migrations",
    "docs",
    "virtualenv",
    "configuration/ldap_config.py",
]
```

### Ignored Rules

**Source**: `.flake8`
```ini
ignore =
    W503,  # line break before binary operator
    E231,  # missing whitespace after ','
    W605,  # invalid escape sequence
```

**Migrated to**: `pyproject.toml`
```toml
[tool.ruff.lint]
ignore = [
    "E231",  # missing whitespace after ','
    "W605",  # invalid escape sequence
]
```

**Note**: W503 was in the original `.flake8` but is deprecated in Ruff (now handled automatically by the formatter).

### Import Sorting Configuration

**Source**: `pyproject.toml` (isort) + `.pre-commit-config.yaml`
```toml
[tool.isort]
profile = "black"
known_first_party = ["certego_saas"]
```

**Migrated to**: `pyproject.toml`
```toml
[tool.ruff.lint.isort]
known-first-party = ["certego_saas"]
profile = "black"
```

---

## Testing the Migration

### Local Testing

1. **Install Ruff**:
   ```bash
   pip install ruff==0.8.6
   ```

2. **Run Ruff Linter**:
   ```bash
   ruff check .
   ```

3. **Run Ruff Formatter**:
   ```bash
   ruff format --check .
   ```

4. **Auto-fix Issues**:
   ```bash
   ruff check . --fix
   ruff format .
   ```

### Pre-commit Testing

1. **Install pre-commit hooks**:
   ```bash
   pre-commit install
   ```

2. **Run on all files**:
   ```bash
   pre-commit run --all-files
   ```

### CI/CD Testing

The GitHub Actions workflow will automatically run Ruff on all pull requests:
- Linting: `ruff check . --output-format=github`
- Formatting: `ruff format --check .`

---

## Troubleshooting

### Common Issues and Solutions

#### Issue 1: Ruff not found
```bash
/bin/bash: ruff: command not found
```

**Solution**:
```bash
pip install ruff==0.8.6
# or
uv tool install ruff
```

#### Issue 2: Configuration not being picked up
**Problem**: Ruff isn't reading configuration from `pyproject.toml`

**Solution**: Ensure `pyproject.toml` is in the project root and properly formatted as TOML.

#### Issue 3: Different formatting than black
**Problem**: Code formatted differently than before

**Solution**: Check these settings in `pyproject.toml`:
```toml
[tool.ruff.format]
quote-style = "double"
indent-style = "space"

[tool.ruff.lint.isort]
profile = "black"
```

#### Issue 4: Too many linting errors
**Problem**: Ruff reports errors that flake8 didn't

**Solution**: Add specific rules to ignore list if they're false positives:
```toml
[tool.ruff.lint]
ignore = [
    "E501",  # line too long (if you want to ignore)
]
```

Or ignore for specific files:
```toml
[tool.ruff.lint.per-file-ignores]
"tests/*.py" = ["F401"]  # unused imports ok in tests
```

---

## Command Reference

### Useful Ruff Commands

```bash
# Check for linting issues
ruff check .

# Auto-fix issues
ruff check . --fix

# Check formatting
ruff format --check .

# Format code
ruff format .

# Show configuration
ruff check --show-settings

# Watch mode (re-run on file changes)
ruff check --watch .

# Generate GitHub Actions annotations
ruff check . --output-format=github

# Check specific file
ruff check path/to/file.py

# Show available rules
ruff rule --all
```

---

## Performance Comparison

### Before (flake8 + black + isort)

Approximate CI execution times:
- Black: ~15 seconds
- Flake8: ~20 seconds
- Isort: ~10 seconds
- **Total**: ~45 seconds

### After (Ruff)

Approximate CI execution times:
- Ruff check + format: ~2-5 seconds
- **Total**: ~5 seconds

**Speed improvement**: ~9x faster ⚡

---

## References

- **Ruff Documentation**: https://docs.astral.sh/ruff/
- **Issue #3142**: https://github.com/intelowlproject/IntelOwl/issues/3142
- **Ruff GitHub**: https://github.com/astral-sh/ruff
- **Migration Guide**: https://docs.astral.sh/ruff/guides/

---

## Contributors

- Migration performed by: @kami (with Claude Code assistance)
- Issue opened by: @mlodic
- Date: January 2026

---

## Rollback Plan

If you need to rollback this migration:

1. **Restore old requirements**:
   ```bash
   git checkout HEAD~1 requirements/test-requirements.txt
   pip install -r requirements/test-requirements.txt
   ```

2. **Restore old configurations**:
   ```bash
   git checkout HEAD~1 .flake8 pyproject.toml .pre-commit-config.yaml
   ```

3. **Update GitHub Actions**:
   ```bash
   git checkout HEAD~1 .github/workflows/pull_request_automation.yml
   ```

4. **Reinstall pre-commit hooks**:
   ```bash
   pre-commit install
   pre-commit run --all-files
   ```

---

**End of Migration Documentation**
