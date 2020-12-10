# Tests

### Configuration
- In the encrypted folder `test_files.zip` (password: "infected") there are some real malware samples that you can use for testing purposes.

**Please remember that these are dangerous malware! They come encrypted and locked for a reason! Do NOT run them unless you are absolutely sure of what you are doing! They are to be used only for launching tests for the file analyzers**

- With the following environment variables you can customize your tests:
    * DISABLE_LOGGING_TEST -> disable logging to get a clear output
    * MOCK_CONNECTIONS -> mock connections to external API to test the analyzers without a real connection or a valid API key

- If you prefer to use custom inputs for tests, you can change the following environment variables in the environment file based on the data you would like to test:
    * TEST_JOB_ID
    * TEST_MD5
    * TEST_URL
    * TEST_IP
    * TEST_DOMAIN
    
### Launch tests
    
- Start the app using the docker-compose test file. In this way, you would launch the code in your environment and not the last official image in Docker Hub:
`docker-compose -f docker/default.yml -f docker/test.override.yml up`

- Run tests from the project directory:
`docker exec -ti intel_owl_uwsgi python3 manage.py test tests`

- Run only a specific test: (example "test_checkdmarc")
`docker exec -ti intel_owl_uwsgi python3 manage.py test tests.test_observables.DomainAnalyzersTests.test_checkdmarc`

- Rebuild the local image after changes were made:
`docker-compose -f docker/default.yml -f docker/test.override.yml build`
    
