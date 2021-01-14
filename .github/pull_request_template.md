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

- [ ] The pull request is for the branch develop
- [ ] If I added a new analyzer, I updated the file [Usage](https://github.com/intelowlproject/IntelOwl/blob/master/docs/source/Usage.md). If the analyzer provides additional optional configuration, I added the available options here: [Advanced-Usage](./Advanced-Usage.md)
- [ ] If I added external libraries/packages that use restrictive licenses, please add them in the [ReadMe - Legal Notice](https://github.com/certego/IntelOwl/blob/master/README.md) section
- [ ] I added new secrets in the files [env_file_app_template](https://github.com/intelowlproject/IntelOwl/blob/master/env_file_app_template), [env_file_app_ci](https://github.com/certego/IntelOwl/blob/master/env_file_app_travis) and in the docs: [Installation](./Installation.md)
- [ ] I have added tests in the [Tests](https://github.com/intelowlproject/IntelOwl/blob/master/tests) folder. 
- [ ] The tests gave 0 errors.
- [ ] `Black` gave 0 errors.
- [ ] `Flake` gave 0 errors.
- [ ] I squashed the commits into a single one.
  
### please follow these rules
- If your changes decrease the overall tests coverage (you will know after the Codecov CI job is done), you should add the required tests to fix the problem
- Everytime you make changes to the PR and you think the work is done, you should explicitly ask for a review

# Real World Example

Please delete if the PR is for bug fixing.
Otherwise, please provide the resulting raw JSON of a finished analysis (and, if you like, a screenshot of the results). This is to allow the maintainers to understand how the analyzer works.
