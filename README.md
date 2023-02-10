[![CI](https://github.com/certego/.github/actions/workflows/pull_request_automation.yml/badge.svg)](https://github.com/certego/.github/actions/workflows/pull_request_automation.yml)

<img src="Certego.png" alt="Certego" width="200" />

# .github

This repository contains CI workflows for Certego projects.
It also contains the recommended configurations for linters and formatters.

## ⚙️ CI components
### 🔴 [Pull request automation](workflows/pull_request_automation.yml)
Automatically executed on every PR. Manages tests and lints stuff. To customize for your project.
### 🔴 [Release](workflows/release.yml)
Automatically executed on every closed PR to the master branch. Manages release stuff. To customize for your project.
## ⇩
### 🟡 [Reusable workflows](workflows/)
They receive input props and call actions.
## ⇩
### 🟢 [Composite actions](actions/)
They execute commands (linters, tests,...)

### CI features
Actually CI actions commands implement this features:
- Linters & Formatters
  - Black
  - Isort
  - Flake8
  - Pylint
  - Bandit
  - Eslint
  - Prettier
  - Stylelint
- Tests 
  - Coverage printing
  - License checks
  - Doc syntax check
  - CodeQL security check
  - Django migrations check
  - Dockerfile syntax check
- Release and tagging
- Publish on test Pypi
- Publish on Pypi
- Publish on Npm
- Announce release on Twitter

### Other CI features:
This repository also contains configurations for:
- [Dependabot](dependabot.yml)
- Pre-commit hook configurations

## 🧰 Action configurations (linters, formatters, docs, coverage...)
See [here](configurations/)

---

## 📖 How to use
Use `git subtree` to add this repository to your project:
```bash
git subtree add --squash --prefix .github https://github.com/certego/.github.git main  && rm -rf .github/.github
```
Customize options of [Pull request automation](workflows/pull_request_automation.yml)
Customize linters in [configurations folder](configurations/)
Customize [dependabot](dependabot.yml).
Customize [CHANGELOG](CHANGELOG.md)
**Note:** every time a new release of this repository is rolled, you have to update the subtree folder.
```bash
git subtree pull --squash --prefix .github https://github.com/certego/.github  main && rm -rf .github/.github

```
Pay attention,be careful to not lose your changes.
Configure your project following below instructions.

### Python
CI automatically installs and calls code analyzers this way:
```
pylint --rcfile=.github/configurations/python_linters/.pylintrc
bandit -c .github/configurations/python_linters/.bandit.yaml
flake8 --config .github/configurations/python_linters/.flake8
black --config .github/configurations/python_linters/.black
isort --settings-path .github/configurations/python_linters/.isort.cfg --profile black --filter-files --skip venv
```
For local installation and customization, see [here](configurations/python_linters/README.md)

#### (Opt.) Pre-commit
Add `pre-commit` to your python requirements.
Configure [this](.pre-commit-config.yaml) configuration file in your `.github` dir.
From root of your project install:
```
pre-commit install -c .github/.pre-commit-config.yaml
```
Pre-commit will add hook `.git/hooks/pre-commit` for you.

### Node.js
Add to `package.json` these scripts (configure paths), CI automatically installs and calls them:
```
"config": {
    "eslint": ".github/configurations/node_linters/eslint/.eslintrc.json",
    "stylelint": ".github/configurations/node_linters/stylelint/.stylelintrc.json",
    "prettier": ".github/configurations/node_linters/prettier/.prettierrc.js"
},
"scripts": {
    "test": "TZ=UTC jest ./tests --silent",
    "test-coverage": "npm test -- --coverage=true",
    "lint-config-install": "cd $(dirname $npm_package_config_eslint) && npm i",
    "lint": "eslint -c $npm_package_config_eslint 'src/**/*.{js,jsx}' 'tests/**/*.{js,jsx}'",
    "lint-fix": "npm run lint -- --fix",
    "lint-scss-config-install": "cd $(dirname $npm_package_config_stylelint) && npm i",
    "lint-scss": "stylelint --config $npm_package_config_stylelint 'src/scss/**/*.{css,scss}'",
    "lint-scss-fix": "npm run lint-scss -- --fix",
    "formatter": "prettier --config $npm_package_config_prettier 'src/**/*.{js,jsx}' 'tests/**/*.{js,jsx}' 'src/scss/**/*.{css,scss}' --check",
    "formatter-fix": "npm run formatter -- --write"
```
For local installation and customization see [here](configurations/node_linters/README.md).

#### (Opt.) Pre-commit
To enable pre-commit add this to your `package.json` (configure paths, prettier is optional).
**Note:** starting point of `husky install` must be same directory as .git
```
    "scripts": {
        "prepare": "cd ./ && husky install .github/.husky"
    },
    "lint_staged": {
        "*.{js,jsx}": ["eslint -c .github/configurations/node_linters/eslint/.eslintrc.json"] //, "prettier --config .github/configurations/node_linters/prettier/.prettierrc.js"],
        "*.{css,scss}": ["stylelint --config .github/configurations/node_linters/stylelint/.stylelintrc.json"] // , "prettier --config .github/configurations/node_linters/prettier/.prettierrc.js"]
    },
```
Then execute this command:
```
npm i -D husky lint-staged && npm run prepare
```


## 🔧 Development
To contribute to this repository, please see [here](README.dev.md)
