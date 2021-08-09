# Contribute

Intel Owl was designed to ease the addition of new analyzers/connectors. With a simple python script you can integrate your own engine or integrate an external service in a short time.

> Wish to contribute to the web interface ? See [IntelOwl-ng](https://github.com/intelowlproject/IntelOwl-ng).

## Code Style
Keeping to a consistent code style throughout the project makes it easier to contribute and collaborate. We make use of [`psf/black`](https://github.com/psf/black) for code formatting and [`flake8`](https://flake8.pycqa.org) for style guides.

## How to start
Please create a new branch based on the **develop** branch that contains the most recent changes. This is mandatory.

`git checkout -b myfeature develop`

Then we strongly suggest to configure [pre-commit](https://github.com/pre-commit/pre-commit) to force linters on every commits you perform:
```bash
# create virtualenv to host pre-commit installation
python3 -m venv intel_owl_test_env
source intel_owl_test_env/bin/activate
# from the project base directory
pip install pre-commit
pre-commit install
```

### Start the development instance
You can execute IntelOwl in development mode by selecting the mode `test` while launching the startup script:
```
python3 start.py test up
```
Every time you perform a change, you should rebuild the containers to have it reflected in the server:
```
python3 start.py test down
python3 start.py test up --build
```
#### Advanced testing configuration
To avoid wasting of time in rebuilding the containers every time, you can also execute the instance with the option `--django-server`:
```
python3 start.py test --django-server up
```
In this way, changes will be instantly reflected to the application server without having to rebuild everything.

However remember that the changes won't be automatically reflected to other containers running the python code like the `celery` ones (that IntelOwl uses to execute analyzers).
This means that you still need to rebuild everything when, for example, you change or create an analyzer.

## How to add a new analyzer
You may want to look at a few existing examples to start to build a new one, such as:
- [shodan.py](https://github.com/intelowlproject/IntelOwl/blob/master/api_app/analyzers_manager/observable_analyzers/shodan.py), if you are creating an observable analyzer
- [intezer_scan.py](https://github.com/intelowlproject/IntelOwl/blob/master/api_app/analyzers_manager/file_analyzers/intezer_scan.py), if you are creating a file analyzer
- [peframe.py](https://github.com/intelowlproject/IntelOwl/blob/master/api_app/analyzers_manager/file_analyzers/peframe.py), if you are creating a [docker based analyzer](#integrating-a-docker-based-analyzer)

After having written the new python module, you have to remember to:
1. Put the module in the `file_analyzers` or `observable_analyzers` directory based on what it can analyze
2. Add a new entry in the [analyzer configuration](https://github.com/intelowlproject/IntelOwl/blob/master/configuration/analyzer_config.json) following alphabetical order:
  
  Example:
  ```javascript
  "Analyzer_Name": {
      "type": "file",
      "python_module": "<module_name>.<class_name>",
      "description": "very cool analyzer",
      "external_service": true,
      "leaks_info": true,
      "run_hash": true,
      "supported_filetypes": ["application/javascript"],
      "config": {
        "soft_time_limit": 100,
        "queue": "long",
      }
      "secrets": {
           "env_var_key": "ANALYZER_SPECIAL_KEY",
           "type": "string",
           "required": true,
           "default": null,
           "description": "API Key for the analyzer",
      }
  },
  ```
  
  Remember to set at least:
  * `type`: can be `file` or `observable`. It specifies what the analyzer should analyze
  * `python_module`: name of the task that the analyzer must launch
  * `description`: little description of the analyzer
  
  The `config` can be used in case the new analyzer uses specific configuration arguments and `secrets` can be used to declare any secrets the analyzer requires in order to run (Example: API Key). 
  In that way you can create more than one analyzer for a specific python module, each one based on different configurations.
  MISP and Yara Analyzers are a good example of this use case: for instance, you can use different analyzers for different MISP instances.

  Please see [Analyzers customization section](./Usage.md#analyzers-customization) to get the explanation of the other available keys.


3. Add the new analyzer in the lists in the docs: [Usage](./Usage.md). Also, if the analyzer provides additional optional configuration, add the available options here: [Advanced-Usage](./Advanced-Usage.md)

4. Ultimately, add the required secrets in the files `docker/env_file_app_template`, `docker/env_file_app_ci` and in the `docs/Installation.md`.

5. In the Pull Request remember to provide some real world examples (screenshots and raw JSON results) of some successful executions of the analyzer to let us understand how it would work.

### Integrating a docker based analyzer
If the analyzer you wish to integrate doesn't exist as a callable API online or python package, it should be integrated with its own docker image
which can be queried from the main Django API.

* It should follow the same design principle as the [Box-Js integration](https://github.com/intelowlproject/IntelOwl/tree/develop/integrations), unless there's very good reason not to.
* The dockerfile should be placed at `./integrations/<analyzer_name>/Dockerfile`.
* Two docker-compose files `compose.yml` for production and `compose-tests.yml` for testing should be placed under `./integrations/<analyzer_name>`.
* If your docker-image uses any environment variables, add them in the `docker/env_file_integrations_template`.
* Rest of the steps remain same as given under "How to add a new analyzer".

## How to add a new connector
You may want to look at a few existing examples to start to build a new one:
- [misp.py](https://github.com/intelowlproject/IntelOwl/blob/master/api_app/connectors_manager/connectors/misp.py)
- [opencti.py](https://github.com/intelowlproject/IntelOwl/blob/master/api_app/connectors_manager/connectors/opencti.py)

After having written the new python module, you have to remember to:
1. Put the module in the `connectors` directory
2. Add a new entry in the [connector configuration](https://github.com/intelowlproject/IntelOwl/blob/master/configuration/connector_config.json) following alphabetical order:
  
  Example:
  ```javascript
  "Connector_Name": {
      "python_module": "<module_name>.<class_name>",
      "description": "very cool connector",
      "config": {
        "soft_time_limit": 100,
        "queue": "default",
      }
      "secrets": {
           "env_var_key": "CONNECTOR_SPECIAL_KEY",
           "type": "string",
           "required": true,
           "default": null,
           "description": "API Key for the connector",
      }
  },
  ```
  
  Remember to set at least:
  * `python_module`: name of the task that the connector must launch
  * `description`: little description of the connector
  
  Similar to analyzers, the `config` can be used in case the new connector uses specific configuration arguments and `secrets` can be used to declare any secrets the connector requires in order to run (Example: API Key).

  Please see [Connectors customization section](./Usage.md#connectors-customization) to get the explanation of the other available keys.


3. Add the new connector in the lists in the docs: [Usage](./Usage.md). Also, if the connector provides additional optional configuration, add the available options here: [Advanced-Usage](./Advanced-Usage.md)
4. Follow steps 4-5 of [How to add a new analyzer](./Contribute.md#how-to-add-a-new-analyzer)

## Create a pull request

### Install testing requirements
Run `pip install -r test-requirements.txt` to install the requirements to validate your code. 

#### Pass linting and tests
1. Run `psf/black` to lint the files automatically and then `flake8` to check:
 
 (if you installed `pre-commit` this is performed automatically at every commit)

```bash
$ black . --exclude "migrations|venv"
$ flake8 . --show-source --statistics
```

  if flake8 shows any errors, fix them.

2. Run the build and start the app using the docker-compose test file. In this way, you would launch the code in your environment and not the last official image in Docker Hub:

```bash
$ python3 start.py ci build
$ python3 start.py ci up
```

3. Here, we simulate the GitHub CI tests locally by running the following 3 tests:

```bash
$ docker exec -ti intelowl_uwsgi unzip -P infected tests/test_files.zip
$ docker exec -ti intelowl_uwsgi python manage.py test tests
```

> Note: IntelOwl has dynamic testing suite. This means that no explicit analyzers/connector tests are required after the addition of a new analyzer or connector.


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
```json
    "Yara_Scan_Custom_Signatures": {
        "type": "file",
        "python_module": "yara.Yara",
        "description": "Executes Yara with custom signatures",
        "config": {
            "directories_with_rules": ["/opt/deploy/yara/custom_signatures"]
        }
    },
```
