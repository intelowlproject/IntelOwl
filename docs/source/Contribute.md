# Contribute

Intel Owl was designed to ease the addition of new analyzers/connectors. With a simple python script you can integrate your own engine or integrate an external service in a short time.

> Wish to contribute to the web interface ? See [IntelOwl-ng](https://github.com/intelowlproject/IntelOwl-ng).

> Wish to contribute to the python client ? See [pyintelowl](https://github.com/intelowlproject/pyintelowl).


## Rules
Intel Owl welcomes contributors from anywhere and from any kind of education or skill level. We strive to create a community of developers that is welcoming, friendly and right.

For this reason it is important to follow some easy rules based on a simple but important concept: **Respect**.

* Before starting to work on an issue, you need to get the approval of one of the maintainers. Therefore please ask to be assigned to an issue. If you do not that but you still raise a PR for that issue, your PR can be rejected. This is a form of respect for both the maintainers and the other contributors who could have already started to work on the same problem.

* When you ask to be assigned to an issue, it means that you are ready to work on it. When you get assigned, take the lock and then you disappear, you are not respecting the maintainers and the other contributors who could be able to work on that. So, after having been assigned, you have a week of time to deliver your first *draft* PR. After that time has passed without any notice, you will be unassigned.

* Before asking questions regarding how the project works, please read *through all the documentation* and [install](https://intelowl.readthedocs.io/en/latest/Installation.html) the project on your own local machine to try it and understand how it basically works. This is a form of respect to the maintainers.

* Once you started working on an issue and you have some work to share and discuss with us, please raise a draft PR early with incomplete changes. This way you can continue working on the same and we can track your progress and actively review and help. This is a form of respect to you and to the maintainers.

* When creating a PR, please read through the sections that you will find in the PR template and compile it appropriately. If you do not, your PR can be rejected. This is a form of respect to the maintainers.

## Code Style
Keeping to a consistent code style throughout the project makes it easier to contribute and collaborate. We make use of [`psf/black`](https://github.com/psf/black) and [isort](https://pycqa.github.io/isort/) for code formatting and [`flake8`](https://flake8.pycqa.org) for style guides.

## How to start (Setup project and development instance)
Please create a new branch based on the **develop** branch that contains the most recent changes. This is mandatory.

`git checkout -b myfeature develop`

Then we strongly suggest to configure [pre-commit](https://github.com/pre-commit/pre-commit) to force linters on every commits you perform:
```bash
# create virtualenv to host pre-commit installation
python3 -m venv venv
source venv/bin/activate
# from the project base directory
pip install pre-commit
pre-commit install

# create .env file for controlling repo_downloader.sh
cp docker/.env.start.test.template docker/.env.start.test
```

Now, you can execute IntelOwl in development mode by selecting the mode `test` while launching the startup script:
```bash
python3 start.py test --django-server up
```
Every time you perform a change, you should rebuild the containers to have it reflected in the server:
```bash
python3 start.py test down
python3 start.py test up --build
```

<div class="admonition hint">
<p class="admonition-title">Hint</p>
<ul>
  <li>
  With the <code>--django-server</code> changes will be instantly reflected to the application server without having to rebuild the docker images.
  </li>
  <li>
  However remember that the changes won't be automatically reflected to other containers running the python code like the "celery" ones (that IntelOwl uses to execute analyzers). This means that you still need to rebuild everything when, for example, when you change or create an analyzer.
  </li>
</div>

## How to add a new analyzer
You may want to look at a few existing examples to start to build a new one, such as:
- [shodan.py](https://github.com/intelowlproject/IntelOwl/blob/develop/api_app/analyzers_manager/observable_analyzers/shodan.py), if you are creating an observable analyzer
- [malpedia_scan.py](https://github.com/intelowlproject/IntelOwl/blob/develop/api_app/analyzers_manager/file_analyzers/malpedia_scan.py), if you are creating a file analyzer
- [peframe.py](https://github.com/intelowlproject/IntelOwl/blob/develop/api_app/analyzers_manager/file_analyzers/peframe.py), if you are creating a [docker based analyzer](#integrating-a-docker-based-analyzer)

After having written the new python module, you have to remember to:
1. Put the module in the `file_analyzers` or `observable_analyzers` directory based on what it can analyze
2. Add a new entry in the [analyzer configuration](https://github.com/intelowlproject/IntelOwl/blob/master/configuration/analyzer_config.json) following alphabetical order:
  
  Example:
  ```javascript
  "Analyzer_Name": {
      "type": "file", // or "observable"
      "python_module": "<module_name>.<class_name>",
      "description": "very cool analyzer",
      "external_service": true,
      "leaks_info": true
      "run_hash": true, // required only for file analyzer
      "observable_supported": ["ip", "domain", "url", "hash", "generic"], // required only for observable analyzer
      "supported_filetypes": ["application/javascript"], // required only for file analyzer
      "config": {
        "soft_time_limit": 100,
        "queue": "long",
      }
      "secrets": {
        "api_key_name": {
          "env_var_key": "ANALYZER_SPECIAL_KEY",
          "type": "string",
          "required": true,
          "default": null,
          "description": "API Key for the analyzer",
        }
      }
  },
  ```
  
  The `config` can be used in case the new analyzer uses specific configuration arguments and `secrets` can be used to declare any secrets the analyzer requires in order to run (Example: API Key, URL, etc.). 
  In that way you can create more than one analyzer for a specific python module, each one based on different configurations.
  MISP and Yara Analyzers are a good example of this use case: for instance, you can use different analyzers for different MISP instances.

  <div class="admonition note">
  <p class="admonition-title">Note</p>
  Please see <a href="Usage.html#analyzers-customization">Analyzers customization section</a> to get the explanation of the other available keys.
  </div>

3. Add the new analyzer in the lists in the docs: [Usage](./Usage.md). Also, if the analyzer provides additional optional configuration, add the available options here: [Advanced-Usage](./Advanced-Usage.md)

4. Ultimately, add the required secrets in the files `docker/env_file_app_template`, `docker/env_file_app_ci` and in the `docs/Installation.md`.

5. In the Pull Request remember to provide some real world examples (screenshots and raw JSON results) of some successful executions of the analyzer to let us understand how it would work.

### Integrating a docker based analyzer
If the analyzer you wish to integrate doesn't exist as a public API or python package, it should be integrated with its own docker image
which can be queried from the main Django app.

* It should follow the same design principle as the [other such existing integrations](https://github.com/intelowlproject/IntelOwl/tree/develop/integrations), unless there's very good reason not to.
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
2. Add a new entry in the [connector_config.json](https://github.com/intelowlproject/IntelOwl/blob/master/configuration/connector_config.json) following alphabetical order:
  
  Example:
  ```javascript
  "Connector_Name": {
      "python_module": "<module_name>.<class_name>",
      "description": "very cool connector",
      "maximum_tlp": "WHITE",
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
  * `maximum_tlp`: maximum TLP of the analysis upto which the connector is allowed to run.
  
  Similar to analyzers, the `config` can be used in case the new connector uses specific configuration arguments and `secrets` can be used to declare any secrets the connector requires in order to run (Example: API Key).

  Please see [Connectors customization section](./Usage.md#connectors-customization) to get the explanation of the other available keys.


3. Add the new connector in the lists in the docs: [Usage](./Usage.md). Also, if the connector provides additional optional configuration, add the available options here: [Advanced-Usage](./Advanced-Usage.md)
4. Follow steps 4-5 of [How to add a new analyzer](./Contribute.md#how-to-add-a-new-analyzer)

## Create a pull request

### Remember!!!
Please create pull requests only for the branch **develop**. That code will be pushed to master only on a new release.

Also remember to pull the most recent changes available in the **develop** branch before submitting your PR. If your PR has merge conflicts caused by this behavior, it won't be accepted.

### Install testing requirements
Run `pip install -r requirements/test-requirements.txt` to install the requirements to validate your code. 

#### Pass linting and tests
1. Run `psf/black` to lint the files automatically, then `flake8` to check and `isort`:
 
 (if you installed `pre-commit` this is performed automatically at every commit)

```bash
$ black . --exclude "migrations|venv"
$ flake8 . --show-source --statistics
$ isort --profile black --filter-files --skip venv
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
