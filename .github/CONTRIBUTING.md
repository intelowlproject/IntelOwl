Please refer to https://intelowlproject.github.io/docs/IntelOwl/contribute/

## Running tests locally

Install the required packages before executing the test suite:

```bash
pip install -r requirements/project-requirements.txt -r requirements/test-requirements.txt
```

The tests depend on Django and other libraries from these files. Missing them
will often result in `ModuleNotFoundError` issues.
