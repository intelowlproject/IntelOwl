# Contribute

Intel Owl was designed to ease the addition of new analyzers. With a simple python script you can integrate your own engine or integrate an external service in a short time.

> Wish to contribute to the web interface ? See [IntelOwl-ng](https://github.com/intelowlproject/IntelOwl-ng).

## Code Style
Keeping to a consistent code style throughout the project makes it easier to contribute and collaborate. We make use of [`psf/black`](https://github.com/psf/black) for code formatting and [`flake8`](https://flake8.pycqa.org) for style guides.

## How to start
Please create a new branch based on the **develop** branch that contains the most recent changes.

`git checkout -b myfeature develop`

## How to add a new analyzer
You may want to look at a few existing examples to start to build a new one, such as:
- [shodan.py](https://github.com/intelowlproject/IntelOwl/blob/develop/api_app/script_analyzers/observable_analyzers/shodan.py), if you are creating an observable analyzer
- [intezer_scan.py](https://github.com/intelowlproject/IntelOwl/blob/develop/api_app/script_analyzers/file_analyzers/intezer_scan.py), if you are creating a file analyzer
- [peframe.py](https://github.com/intelowlproject/IntelOwl/blob/develop/api_app/script_analyzers/file_analyzers/peframe.py), if you creating a [docker based analyzer](#integrating-a-docker-based-analyzer)

After having written the new python module, you have to remember to:
* Put the module in the `file_analyzers` or `observable_analyzers` directory based on what it can analyze
* Add the new module as a celery task in [tasks.py](https://github.com/intelowlproject/IntelOwl/blob/master/intel_owl/tasks.py)
* Add a new entry in the [analyzer configuration](https://github.com/intelowlproject/IntelOwl/blob/master/configuration/analyzer_config.json) following alphabetical order:
  
  Example:
  ```
  "Analyzer_Name": {
      "type": "file",
      "external_service": true,
      "leaks_info": true,
      "run_hash": true,
      "supported_filetypes": ["application/javascript"],
      "python_module": "haget_run",
      "additional_config_params": {
           "custom_required_param": "ANALYZER_SPECIAL_KEY"
      }
  },
  ```
  
  Remember to set at least:
  * `type`: can be `file` or `observable`. It specifies what the analyzer should analyze
  * `python_module`: name of the task that the analyzer must launch
  * `description`: little description of the analyzer
  * `requires_configuration`: if the analyzer requires a configuration made by the user (for example setting an API key)
  
  The `additional_config_params` can be used in case the new analyzer requires additional configuration.
  In that way you can create more than one analyzer for a specific python module, each one based on different configurations.
  MISP and Yara Analyzers are a good example of this use case: for instance, you can use different analyzers for different MISP instances.

* Add required unit tests in the [tests](https://github.com/intelowlproject/IntelOwl/blob/master/tests) folder
 
  Then follow the [Test](./Tests.md) guide to start testing.

* Add the new analyzer/s in the lists in the docs: [Usage](./Usage.md) and [ReadMe](https://github.com/intelowlproject/IntelOwl/blob/master/README.md)

* Ultimately, add the required secrets in the files [env_file_app_template](https://github.com/intelowlproject/IntelOwl/blob/master/env_file_app_template), [env_file_app_travis](https://github.com/certego/IntelOwl/blob/master/env_file_app_travis) and in the docs: [Installation](./Installation.md)

### Integrating a docker based analyzer
If the analyzer you wish to integrate doesn't exist as a callable API online or python package, it should be integrated with its own docker image
which can be queried from the main Django API.

* It should follow the same design principle as the [PEframe's integration](https://github.com/intelowlproject/IntelOwl/tree/develop/integrations), unless there's very good reason not to.
* The dockerfile should be placed at `./integrations/<analyzer_name>/Dockerfile`.
* A docker-compose file should be placed under `./integrations` with the name `docker-compose.<analyzer_name>.yml`
* If your docker-image uses any environment variables, add them in the [`env_file_integrations_template`](https://github.com/intelowlproject/IntelOwl/blob/develop/env_file_integrations_template)
* Ultimately, append the name of your docker-compose file in the `COMPOSE_FILE` variables specified in [`.env`](https://github.com/intelowlproject/IntelOwl/blob/develop/.env). The reason for doing this is so that this service remains optional to the end-user.
* Rest of the steps remain same as given under "How to add a new analyzer".

### Create a pull request

#### Pass linting and tests
1. Run `psf/black` to lint the files automatically and then `flake8` to check,

```bash
$ black . --exclude "migrations|venv"
$ flake8 . --show-source --statistics
```

  if flake8 shows any errors, fix them.

2. Run the build and start the app using the docker-compose test file. In this way, you would launch the code in your environment and not the last official image in Docker Hub:

```bash
$ docker-compose -f docker-compose-for-tests.yml build
$ docker-compose -f docker-compose-for-tests.yml up`
```

3. Here, we simulate the travis CI tests locally by running the following 3 tests,

```bash
$ docker exec -ti intel_owl_uwsgi black . --check --exclude "migrations|venv"
$ docker exec -ti intel_owl_uwsgi flake8 . --count
$ docker exec -ti intel_owl_uwsgi python manage.py test tests
```

Please make sure all 3 of these tests return positively.

If everything is working, before submitting your pull request, please squash your commits into a single one!

#### How to squash commits to a single one

* Run `git rebase -i HEAD~[NUMBER OF COMMITS]`
* You should see a list of commits, each commit starting with the word "pick".
* Make sure the first commit says "pick" and change the rest from "pick" to "squash". -- This will squash each commit into the previous commit, which will continue until every commit is squashed into the first commit.
* Save and close the editor.
* It will give you the opportunity to change the commit message.
* Save and close the editor again.
* Then you have to force push the final, squashed commit: `git push --force-with-lease origin`.

Squashing commits can be a tricky process but once you figure it out, it's really helpful and keeps our repo concise and clean.

#### Remember!!!
Please create pull requests only for the branch **develop**. That code will be pushed to master only on a new release.

Also remember to pull the most recent changes available in the **develop** branch before submitting your PR. If your PR has merge conflicts caused by this behavior, it won't be accepted.

### Example: add an analyzer configuration for your own Yara signatures
```
    "Yara_Scan_Custom_Signatures": {
        "type": "file",
        "python_module": "yara_run",
        "additional_config_params": {
            "directories_with_rules": ["/opt/deploy/yara/custom_signatures"]
        }
    },
```