# Ruff Quick Start Guide for IntelOwl Contributors

## What is Ruff?

Ruff is an extremely fast Python linter and formatter written in Rust. It replaces flake8, black, and isort in IntelOwl.

---

## Installation

### Using pip
```bash
pip install ruff==0.8.6
```

### Using uv (recommended)
```bash
uv tool install ruff
```

---

## Basic Usage

### Check Code (Linting)
```bash
# Check entire project
ruff check .

# Check specific file
ruff check path/to/file.py

# Auto-fix issues
ruff check . --fix
```

### Format Code
```bash
# Check formatting (doesn't modify files)
ruff format --check .

# Format files
ruff format .

# Format specific file
ruff format path/to/file.py
```

---

## Pre-commit Integration

### Install Pre-commit Hooks
```bash
# Install the hooks
pre-commit install

# Run on all files
pre-commit run --all-files

# Run on staged files only
pre-commit run
```

---

## Common Workflows

### Before Committing
```bash
# 1. Check and fix linting issues
ruff check . --fix

# 2. Format code
ruff format .

# 3. Run pre-commit hooks
pre-commit run

# 4. Stage and commit
git add .
git commit -m "Your commit message"
```

### Checking PR Before Push
```bash
# Run the same checks as CI
ruff check . --output-format=github
ruff format --check .
```

---

## Configuration

All Ruff configuration is in `pyproject.toml`:

```toml
[tool.ruff]
line-length = 140              # Max line length
target-version = "py311"       # Python version

[tool.ruff.lint]
select = ["E", "W", "F", "I"]  # Enabled rules
ignore = ["W503", "E231"]      # Ignored rules

[tool.ruff.format]
quote-style = "double"         # Use double quotes
indent-style = "space"         # Use spaces (not tabs)
```

---

## Troubleshooting

### Ruff Command Not Found
```bash
# Check if installed
ruff --version

# Install if missing
pip install ruff==0.8.6
```

### Different Results Than CI
```bash
# Use same format as CI
ruff check . --output-format=github
```

### Too Many Errors
```bash
# Show errors with context
ruff check . --show-source

# See which rule is triggering
ruff check . --show-fixes
```

---

## Rule Categories

| Code | Category | Replaces |
|------|----------|----------|
| `E`, `W` | pycodestyle | flake8 |
| `F` | Pyflakes | flake8 |
| `I` | isort | isort |
| `DJ` | Django | flake8-django |
| `B` | Bugbear | flake8-bugbear |
| `C4` | Comprehensions | flake8-comprehensions |

---

## Useful Commands

```bash
# Show Ruff configuration
ruff check --show-settings

# List all available rules
ruff rule --all

# Show specific rule details
ruff rule E501

# Check diff against baseline
ruff check --diff

# Output JSON for tooling
ruff check . --output-format=json
```

---

## IDE Integration

### VSCode
Install the [Ruff extension](https://marketplace.visualstudio.com/items?itemName=charliermarsh.ruff)

### PyCharm
Install the [Ruff plugin](https://plugins.jetbrains.com/plugin/20574-ruff)

### Neovim
Use [ruff-lsp](https://github.com/astral-sh/ruff-lsp)

---

## Migration from Old Tools

| Old Command | New Command |
|-------------|-------------|
| `black .` | `ruff format .` |
| `black . --check` | `ruff format --check .` |
| `flake8 .` | `ruff check .` |
| `isort .` | `ruff check . --select I --fix` |

---

## Need Help?

- **Documentation**: https://docs.astral.sh/ruff/
- **Full Migration Doc**: See `MIGRATION_TO_RUFF.md`
- **Issue Tracker**: https://github.com/astral-sh/ruff/issues

---

**Quick Tip**: Run `ruff check . --fix && ruff format .` before every commit! ⚡
