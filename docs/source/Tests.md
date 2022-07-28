# Tests

IntelOwl makes use of the django testing framework and the `unittest` library for unit testing of the API endpoints and End-to-End testing of the analyzers, connectors and playbooks.

### Configuration
- In the encrypted folder `test_files.zip` (password: "infected") there are some real malware samples that you can use for testing purposes.

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

> Note: You may need to rebuild the docker containers on every change.

### Launch tests

Now that the containers are up, we can launch the test suite. There are two helper scripts available for launching tests namely, `coverage_test.sh` and the `test_analyzers.sh`.

##### Run all tests

Examples:

```bash
$ docker/scripts/coverage_test.sh tests
```

##### Run tests available in a particular file

Examples:

```bash
$ docker/scripts/coverage_test.sh tests.test_api tests.test_auth # dotted paths
```

##### Run tests for a particular analyzer or class of analyzers

Syntax:

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