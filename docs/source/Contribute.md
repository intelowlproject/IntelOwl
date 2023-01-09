# Contribute

Intel Owl was designed to ease the addition of new analyzers, connectors and playbooks. With a simple python script you can integrate your own engine or integrate an external service in a short time.

* Wish to contribute to the Python client ? See [pyintelowl](https://github.com/intelowlproject/pyintelowl).

* Wish to contribute to the GO client ? See [go-intelowl](https://github.com/intelowlproject/go-intelowl).

* Wish to contribute to the official IntelOwl Site ? See [intelowlproject.github.io](https://github.com/intelowlproject/intelowlproject.github.io).

## Rules

Intel Owl welcomes contributors from anywhere and from any kind of education or skill level. We strive to create a community of developers that is welcoming, friendly and right.

For this reason it is important to follow some easy rules based on a simple but important concept: **Respect**.

- Before starting to work on an issue, you need to get the approval of one of the maintainers. Therefore please ask to be assigned to an issue. If you do not that but you still raise a PR for that issue, your PR can be rejected. This is a form of respect for both the maintainers and the other contributors who could have already started to work on the same problem.

- When you ask to be assigned to an issue, it means that you are ready to work on it. When you get assigned, take the lock and then you disappear, you are not respecting the maintainers and the other contributors who could be able to work on that. So, after having been assigned, you have a week of time to deliver your first _draft_ PR. After that time has passed without any notice, you will be unassigned.

- Before asking questions regarding how the project works, please read _through all the documentation_ and [install](https://intelowl.readthedocs.io/en/latest/Installation.html) the project on your own local machine to try it and understand how it basically works. This is a form of respect to the maintainers.

- Once you started working on an issue and you have some work to share and discuss with us, please raise a draft PR early with incomplete changes. This way you can continue working on the same and we can track your progress and actively review and help. This is a form of respect to you and to the maintainers.

- When creating a PR, please read through the sections that you will find in the PR template and compile it appropriately. If you do not, your PR can be rejected. This is a form of respect to the maintainers.

## Code Style

Keeping to a consistent code style throughout the project makes it easier to contribute and collaborate. We make use of [`psf/black`](https://github.com/psf/black) and [isort](https://pycqa.github.io/isort/) for code formatting and [`flake8`](https://flake8.pycqa.org) for style guides.

## How to start (Setup project and development instance)

Create a personal fork of the project on Github.
The, please create a new branch based on the **develop** branch that contains the most recent changes. This is mandatory.

`git checkout -b myfeature develop`

Then we strongly suggest to configure [pre-commit](https://github.com/pre-commit/pre-commit) to force linters on every commits you perform

```bash
# create virtualenv to host pre-commit installation
python3 -m venv venv
source venv/bin/activate
# from the project base directory
pip install pre-commit
pre-commit install

# create .env file for controlling repo_downloader.sh (to speed up image builds during development)
cp docker/.env.start.test.template docker/.env.start.test
```

### Backend

Now, you can execute IntelOwl in development mode by selecting the mode `test` while launching the startup script:

```bash
python3 start.py test up
```

Every time you perform a change, you should perform an operation to reflect the changes into the application:

- if you changed the python requirements, restart the application and re-build the images. This is the slowest process. You can always choose this way but it would waste a lot of time.

```bash
python3 start.py test down && python3 start.py test up --build
```

- if you changed either analyzers, connectors, playbooks or anything that is executed asynchronously by the "celery" containers, you just need to restart the application because we leverage Docker bind volumes that will reflect the changes to the containers. This saves the time of the build

```bash
python3 start.py test down && python3 start.py test up
```

- if you made changes to either the API or anything that is executed only by the application server, changes will be instantly reflected and you don't need to do anything. This is thanks to the Django Development server that is executed instead of `uwsgi` while using the `test` mode

#### NOTE about documentation:

If you made any changes to an existing model/serializer/view, please run the following command to generate a new version of the API schema and docs:

```bash
docker exec -it intelowl_uwsgi python manage.py spectacular --file docs/source/schema.yml && make html
```

### Frontend

To start the frontend in "develop" mode, you can execute the startup npm script within the folder `frontend`:

```bash
cd frontend/
# Install
npm i
# Start
DANGEROUSLY_DISABLE_HOST_CHECK=true npm start
# See https://create-react-app.dev/docs/proxying-api-requests-in-development/#invalid-host-header-errors-after-configuring-proxy for why we use that flag in development mode
```

Most of the time you would need to test the changes you made together with the backend. In that case, you would need to run the backend locally too:

```commandline
python3 start.py prod up
```

<div class="admonition note">
<p class="admonition-title">Note</p>
<ul>
<li>Running `prod` would be faster because you would leverage the official images and you won't need to build the backend locally. In case you would need to test backend changes too at the same time, please use `test` and refer to the previous section of the documentation.</li>
<li>This works thanks to the directive `proxy` in the `frontend/package.json` configuration</li>
<li>It may happen that the backend build does not work due to incompatibility between the frontend version you are testing with the current complete IntelOwl version you are running. In those cases, considering that you don't need to build the frontend together with the backend because you are already testing it separately, we suggest to remove the first build step (the frontend part) from the main Dockerfile temporarily and build IntelOwl with only the backend. In this way there won't be conflict issues.</li>
</ul>
</div>

#### Certego-UI

The IntelOwl Frontend is tightly linked to the [`certego-ui`](https://github.com/certego/certego-ui) library. Most of the React components are imported from there. Because of this, it may happen that, during development, you would need to work on that library too.
To install the `certego-ui` library, please take a look to [npm link](https://docs.npmjs.com/cli/v8/commands/npm-link) and remember to start certego-ui without installing peer dependencies (to avoid conflicts with IntelOwl dependencies):

```bash
git clone https://github.com/certego/certego-ui.git
# change directory to the folder where you have the cloned the library
cd certego-ui/
# install, without peer deps (to use packages of IntelOwl)
npm i --legacy-peer-deps
# create link to the project (this will globally install this package)
sudo npm link
# compile the library
npm start
```

Then, open another command line tab, create a link in the `frontend` to the `certego-ui` and re-install and re-start the frontend application (see previous section):

```bash
cd frontend/
npm link @certego/certego-ui
```

This trick will allow you to see reflected every changes you make in the `certego-ui` directly in the running `frontend` application.

##### Example application

The `certego-ui` application comes with an example project that showcases the components that you can re-use and import to other projects, like IntelOwl:

```bash
# To have the Example application working correctly, be sure to have installed `certego-ui` *without* the `--legacy-peer-deps` option and having it started in another command line
cd certego-ui/
npm i
npm start
# go to another tab
cd certego-ui/example/
npm i
npm start
```

## How to add a new analyzer

You may want to look at a few existing examples to start to build a new one, such as:

- [shodan.py](https://github.com/intelowlproject/IntelOwl/blob/develop/api_app/analyzers_manager/observable_analyzers/shodan.py), if you are creating an observable analyzer 
- [malpedia_scan.py](https://github.com/intelowlproject/IntelOwl/blob/develop/api_app/analyzers_manager/file_analyzers/malpedia_scan.py), if you are creating a file analyzer
- [peframe.py](https://github.com/intelowlproject/IntelOwl/blob/develop/api_app/analyzers_manager/file_analyzers/peframe.py), if you are creating a [docker based analyzer](#integrating-a-docker-based-analyzer)
- **Please note:** If the new analyzer that you are adding is free for the user to use, please add it in the `FREE_TO_USE_ANALYZERS` playbook in `playbook_config.json`.

After having written the new python module, you have to remember to:

1. Put the module in the `file_analyzers` or `observable_analyzers` directory based on what it can analyze
2. Add a new entry in the [analyzer configuration](https://github.com/intelowlproject/IntelOwl/blob/master/configuration/analyzer_config.json) following alphabetical order:

Example:

```javascript
"Analyzer_Name": {
    "type": "file", // or "observable"
    "python_module": "<module_name>.<class_name>",
    "description": "very cool analyzer",
    "disabled": false,
    "external_service": true,
    "leaks_info": true,
    "run_hash": true, // required only for file analyzer
    "observable_supported": ["ip", "domain", "url", "hash", "generic"], // required only for observable analyzer
    "supported_filetypes": ["application/javascript"], // required only for file analyzer
    "config": {
      "soft_time_limit": 100,
      "queue": "long",
    },
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

3. Remember to use `_monkeypatch()` in its class to create automated tests for the new analyzer. This is a trick to have tests in the same class of its analyzer.

4. If a File analyzer was added, define its name in [test_file_scripts.py](https://github.com/intelowlproject/IntelOwl/blob/master/tests/analyzers_manager/test_file_scripts.py) (not required for Observable Analyzers).

5. Add the new analyzer in the lists in the docs: [Usage](./Usage.md). Also, if the analyzer provides additional optional configuration, add the available options here: [Advanced-Usage](./Advanced-Usage.html#analyzers-with-special-configuration)

6. Ultimately, add the required secrets in the files `docker/env_file_app_template`, `docker/env_file_app_ci` and in the `docs/Installation.md`.

7. In the Pull Request remember to provide some real world examples (screenshots and raw JSON results) of some successful executions of the analyzer to let us understand how it would work.

### Integrating a docker based analyzer

If the analyzer you wish to integrate doesn't exist as a public API or python package, it should be integrated with its own docker image
which can be queried from the main Django app.

- It should follow the same design principle as the [other such existing integrations](https://github.com/intelowlproject/IntelOwl/tree/develop/integrations), unless there's very good reason not to.
- The dockerfile should be placed at `./integrations/<analyzer_name>/Dockerfile`.
- Two docker-compose files `compose.yml` for production and `compose-tests.yml` for testing should be placed under `./integrations/<analyzer_name>`.
- If your docker-image uses any environment variables, add them in the `docker/env_file_integrations_template`.
- Rest of the steps remain same as given under "How to add a new analyzer".

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

- `python_module`: name of the task that the connector must launch
- `description`: little description of the connector
- `maximum_tlp`: maximum TLP of the analysis up to which the connector is allowed to run.

Similar to analyzers, the `config` can be used in case the new connector uses specific configuration arguments and `secrets` can be used to declare any secrets the connector requires in order to run (Example: API Key).

Please see [Connectors customization section](./Usage.md#connectors-customization) to get the explanation of the other available keys.

3. Add the new connector in the lists in the docs: [Usage](./Usage.md). Also, if the connector provides additional optional configuration, add the available options here: [Advanced-Usage](./Advanced-Usage.md)
4. Follow steps 4-5 of [How to add a new analyzer](./Contribute.md#how-to-add-a-new-analyzer)

## How to add a new Playbook

You may want to look at the existing [playbook_configuration.json](https://github.com/intelowlproject/IntelOwl/blob/master/configuration/playbooks_config.json) file. To set up a new Playbook, Add a new entry to the configuraions file in alphabetical order:

Example:

```javascript
"Playbook_Name": {
    "description": "very cool playbook",
    "analyzers": {
            "AbuseIPDB": {},
            "Shodan": {
                "include_honeyscore": true
            },
            "FireHol_IPList": {}
    },
    "connectors": {
            "MISP": {
                "ssl_check": true
            },
            "OpenCTI": {
                "ssl_verify": true
            }
    }
},
```

Here, The parameters for the analyzers and connectors to be used go in as an entry in the dictionary value.

#### Modifying functionalities of the Certego packages

Since v4, IntelOwl leverages some packages from Certego:

- [certego-saas](https://github.com/certego/certego-saas) that integrates some common reusable Django applications and tools that can be used for generic services.
- [certego-ui](https://github.com/certego/certego-ui) that contains reusable React components for the UI.

If you need to modify the behavior or add feature to those packages, please follow the same rules for IntelOwl and request a Pull Request there. The same maintainers of IntelOwl will answer to you.

Follow these guides to understand how to start to contribute to them while developing for IntelOwl:

- _certego-saas_: create a fork, commit your changes in your local repo, then change the commit hash to the last one you made in the [requirements file](https://github.com/intelowlproject/IntelOwl/blob/master/requirements/certego-requirements.txt). Ultimately re-build the project
- _certego-ui_: [Frontend doc](./Contribute.md#certego-ui)

## How to test the application

IntelOwl makes use of the django testing framework and the `unittest` library for unit testing of the API endpoints and End-to-End testing of the analyzers and connectors.

### Configuration
- In the encrypted folder `tests/test_files.zip` (password: "infected") there are some real malware samples that you can use for testing purposes.

<div class="admonition danger">
<p class="admonition-title">Danger</p>
<strong>
Please remember that these are dangerous malware! They come encrypted and locked for a reason! Do NOT run them unless you are absolutely sure of what you are doing! They are to be used only for launching tests for the file analyzers
</strong>
</div>

- With the following environment variables you can customize your tests:
    * `DISABLE_LOGGING_TEST` -> disable logging to get a clear output
    * `MOCK_CONNECTIONS` -> mock connections to external API to test the analyzers without a real connection or a valid API key

- If you prefer to use custom inputs for tests, you can change the following environment variables in the environment file based on the data you would like to test:
    * `TEST_JOB_ID`
    * `TEST_MD5`
    * `TEST_URL`
    * `TEST_IP`
    * `TEST_DOMAIN`

### Setup containers

The point here is to launch the code in your environment and not the last official image in Docker Hub. 
For this, use the `test` or the `ci` option when launching the containers with the `start.py` script.
- Use the `test` option to _actually_ execute tests that simulate a real world environment without mocking connections.
- Use the `ci` option to execute tests in a CI environment where connections are mocked.

```bash
$ python3 start.py test up
$ # which corresponds to the command: docker-compose -f docker/default.yml -f docker/test.override.yml up
```

### Launch tests

Now that the containers are up, we can launch the test suite.

##### Run all tests

Examples:

```bash
$ docker exec intelowl_uwsgi python3 manage.py test
```

##### Run tests available in a particular file

Examples:

```bash
$ docker exec intelowl_uwsgi python3 manage.py test tests.test_api tests.test_auth # dotted paths
```

##### Run tests for a particular analyzer or class of analyzers
You can leverage an helper script. Syntax:

```bash
$ docker/scripts/test_analyzers.sh <analyzer_class> <comma_separated_analyzer_names>
```

Examples:

- Observable analyzers tests:

    ```bash
    $ docker/scripts/test_analyzers.sh ip Shodan_Honeyscore,Darksearch_Query # run only the specified analyzers
    $ docker/scripts/test_analyzers.sh domain # run all domain analyzers
    ```

    supports: `ip`, `domain`, `url`, `hash`, `generic`.
        
- File analyzers tests:

    ```bash
    $ docker/scripts/test_analyzers.sh exe File_Info,PE_Info # run only the specified analyzers
    $ docker/scripts/test_analyzers.sh pdf # run all PDF analyzers
    ```

    supports: `exe`, `dll`, `doc`, `excel`, `rtf`, `html`, `pdf`, `js`, `apk`.

Otherwise, you can use the normal Django syntax like previously shown. Example:
```bash
$ docker exec intelowl_uwsgi python3 manage.py test tests.analyzers_manager.test_observable_scripts.GenericAnalyzersTestCase
```


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
$ docker exec -ti intelowl_uwsgi unzip -P infected tests/test_files.zip -d test_files
$ docker exec -ti intelowl_uwsgi python manage.py test tests
```

> Note: IntelOwl has dynamic testing suite. This means that no explicit analyzers/connector tests are required after the addition of a new analyzer or connector.

If everything is working, before submitting your pull request, please squash your commits into a single one!

#### How to squash commits to a single one

- Run `git rebase -i HEAD~[NUMBER OF COMMITS]`
- You should see a list of commits, each commit starting with the word "pick".
- Make sure the first commit says "pick" and change the rest from "pick" to "squash". -- This will squash each commit into the previous commit, which will continue until every commit is squashed into the first commit.
- Save and close the editor.
- It will give you the opportunity to change the commit message.
- Save and close the editor again.
- Then you have to force push the final, squashed commit: `git push --force-with-lease origin`.

Squashing commits can be a tricky process but once you figure it out, it's really helpful and keeps our repo concise and clean.
