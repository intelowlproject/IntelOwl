(Please add to the PR name the issue/s that this PR would close if merged by using a [Github](https://docs.github.com/en/issues/tracking-your-work-with-issues/linking-a-pull-request-to-an-issue) keyword. Example: `<feature name>. Closes #999`. If your PR is made by a single commit, please add that clause in the commit too. This is all required to automate the closure of related issues.)

# Description

Please include a summary of the change and link to the related issue.

## Type of change

Please delete options that are not relevant.

- [ ] Bug fix (non-breaking change which fixes an issue).
- [ ] New feature (non-breaking change which adds functionality).
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected).

# Checklist

- [ ] I have read and understood the rules about [how to Contribute](https://intelowlproject.github.io/docs/IntelOwl/contribute/) to this project
- [ ] The pull request is for the branch `develop`
- [ ] A new plugin (analyzer, connector, visualizer, playbook, pivot or ingestor) was added or changed, in which case:
    - [ ] I strictly followed the documentation ["How to create a Plugin"](https://intelowlproject.github.io/docs/IntelOwl/contribute/#how-to-add-a-new-plugin)
    - [ ] [Usage](https://github.com/intelowlproject/docs/blob/main/docs/IntelOwl/usage.md) file was updated. A link to the PR to the [docs](https://github.com/intelowlproject/docs) repo has been added as a comment here.
    - [ ] [Advanced-Usage](https://github.com/intelowlproject/docs/blob/main/docs/IntelOwl/advanced_usage.md) was updated (in case the plugin provides additional optional configuration). A link to the PR to the [docs](https://github.com/intelowlproject/docs) repo has been added as a comment here.
    - [ ] I have dumped the configuration from Django Admin using the `dumpplugin` command and added it in the project as a data migration. (["How to share a plugin with the community"](https://intelowlproject.github.io/docs/IntelOwl/contribute/#how-to-share-your-plugin-with-the-community))
    - [ ] If a File analyzer was added and it supports a mimetype which is not already supported, you added a sample of that type inside the archive `test_files.zip` and you added the default tests for that mimetype in [test_classes.py](https://github.com/intelowlproject/IntelOwl/blob/master/tests/api_app/analyzers_manager/test_classes.py).
    - [ ] If you created a new analyzer and it is free (does not require any API key), please add it in the `FREE_TO_USE_ANALYZERS` playbook by following [this guide](https://intelowlproject.github.io/docs/IntelOwl/contribute/#how-to-modify-a-plugin).
    - [ ] Check if it could make sense to add that analyzer/connector to other [freely available playbooks](https://intelowlproject.github.io/docs/IntelOwl/usage/#list-of-pre-built-playbooks).
    - [ ] I have provided the resulting raw JSON of a finished analysis and a screenshot of the results.
    - [ ] If the plugin interacts with an external service, I have created an attribute called precisely `url` that contains this information. This is required for Health Checks (HEAD HTTP requests). 
    - [ ] If a new analyzer has beed added, I have created a unittest for it in the appropriate dir. I have also mocked all the external calls, so that no real calls are being made while testing.
    - [ ] I have added that raw JSON sample to the `get_mocker_response()` method of the unittest class. This serves us to provide a valid sample for testing. 
    - [ ] I have created the corresponding `DataModel` for the new analyzer following the [documentation](https://intelowlproject.github.io/docs/IntelOwl/contribute/#how-to-create-a-datamodel)
- [ ] I have inserted the copyright banner at the start of the file: ```# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl # See the file 'LICENSE' for copying permission.```
- [ ] Please avoid adding new libraries as requirements whenever it is possible. Use new libraries only if strictly needed to solve the issue you are working for. In case of doubt, ask a maintainer permission to use a specific library.
- [ ] If external libraries/packages with restrictive licenses were added, they were added in the [Legal Notice](https://github.com/certego/IntelOwl/blob/master/.github/legal_notice.md) section.
- [ ] Linters (`Ruff`) gave 0 errors. If you have correctly installed [pre-commit](https://intelowlproject.github.io/docs/IntelOwl/contribute/#how-to-start-setup-project-and-development-instance), it does these checks and adjustments on your behalf.
- [ ] I have added tests for the feature/bug I solved (see `tests` folder). All the tests (new and old ones) gave 0 errors.
- [ ] If the GUI has been modified:
    - [ ] I have a provided a screenshot of the result in the PR.
    - [ ] I have created new frontend tests for the new component or updated existing ones.
- [ ] After you had submitted the PR, if `DeepSource`, `Django Doctors` or other third-party linters have triggered any alerts during the CI checks, I have solved those alerts.

### Important Rules
- If you miss to compile the Checklist properly, your PR won't be reviewed by the maintainers.
- Everytime you make changes to the PR and you think the work is done, you should explicitly ask for a review by using GitHub's reviewing system detailed [here](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/requesting-a-pull-request-review).