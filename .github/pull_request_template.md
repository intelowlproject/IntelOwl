# Description

Please include a summary of the change.

## Related issues
Please add related issues.

## Type of change

Please delete options that are not relevant.

- [ ] Bug fix (non-breaking change which fixes an issue).
- [ ] New feature (non-breaking change which adds functionality).
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected).

# Checklist

- [ ] I have read and understood the rules about [how to Contribute](https://intelowl.readthedocs.io/en/latest/Contribute.html) to this project
- [ ] The pull request is for the branch `develop`
- [ ] A new analyzer or connector was added, in which case:
    - [ ] [Usage](https://github.com/intelowlproject/IntelOwl/blob/master/docs/source/Usage.md) file was updated.
    - [ ] [Advanced-Usage](./Advanced-Usage.md) was updated (in case the analyzer/connector provides additional optional configuration).
    - [ ] Secrets were added in [env_file_app_template](https://github.com/intelowlproject/IntelOwl/blob/master/docker/env_file_app_template), [env_file_app_ci](https://github.com/certego/IntelOwl/blob/master/docker/env_file_app_ci) and in the [Installation](./Installation.md) docs, if necessary.
    - [ ] If the analyzer/connector requires mocked testing, `_monkeypatch()` was used in it's class to apply the necessary decorators.
    - [ ] If a File analyzer was added, it's name was explicitly defined in [test_file_scripts.py](https://github.com/intelowlproject/IntelOwl/blob/master/tests/analyzers_manager/test_file_scripts.py) (not required for Observable Analyzers).
- [ ] If external libraries/packages with restrictive licenses were used, they were added in the [Legal Notice](https://github.com/certego/IntelOwl/blob/master/.github/legal_notice.md) section.
- [ ] The tests gave 0 errors.
- [ ] Linters (`Black`, `Flake`, `Isort`) gave 0 errors. If you have correctly installed [pre-commit](https://intelowl.readthedocs.io/en/latest/Contribute.html#how-to-start-setup-project-and-development-instance), it does these checks and adjustments on your behalf.
- [ ] The commits were squashed into a single one (optional, they will be squashed anyway by the maintainer)
  
### Important Rules
- If your changes decrease the overall tests coverage (you will know after the Codecov CI job is done), you should add the required tests to fix the problem
- Everytime you make changes to the PR and you think the work is done, you should explicitly ask for a review

# Real World Example

Please delete if the PR is for bug fixing.
Otherwise, please provide the resulting raw JSON of a finished analysis (and, if you like, a screenshot of the results). This is to allow the maintainers to understand how the analyzer works.
