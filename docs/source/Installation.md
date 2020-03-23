# Installation

## Deployment options
* Docker-compose for classic server deployment
* (Future) Docker for serverless deployment (ex: AWS Fargate)

We suggest you to clone the project, configure the required environment variables and run `docker-compose up` using the docker-compose file that is embedded in the project.

That file leverages a public docker image that is available in [Docker Hub](https://hub.docker.com/repository/docker/certego/intelowl)

## Deployment Info
Main components of the web application:
* Django
* Rabbit-MQ
* Celery (for async calls and crons)
* Nginx
* Uwsgi
* Flower (optional)

All these components are managed by docker-compose

Database: PostgreSQL

## Deployment preparation
### Environment configuration
Before running the project, you must populate some environment variables in a file to provide the required configuration.
In the project you can find a template file named `env_file_app_template`.
You have to create a new file named `env_file_app` from that template and modify it with your own configuration.

Required variables to run the image:
* DJANGO_SECRET: random 50 chars key, must be unique, generate it randomly
* DB_HOST, DB_PORT, DB_USER, DB_PASSWORD: PostgreSQL configuration

Optional variables needed to enable specific analyzers:
* ABUSEIPDB_KEY: AbuseIPDB API key
* SHODAN_KEY: Shodan API key
* HUNTER_API_KEY: Hunter.io API key
* GSF_KEY: Google Safe Browsing API key
* OTX_KEY: Alienvault OTX API key
* CIRCL_CREDENTIALS: CIRCL PDNS credentials in the format: `user|pass`
* VT_KEY: VirusTotal API key
* HA_KEY: HybridAnalysis API key
* INTEZER_KEY: Intezer API key
* FIRST_MISP_API: FIRST MISP API key
* FIRST_MISP_URL: FIRST MISP URL
* CUCKOO_URL: your cuckoo instance URL
* HONEYDB_API_ID & HONEYDB_API_KEY: HoneyDB credentials
* CENSYS_API_ID & CENSYS_API_SECRET: Censys credentials
* ONYPHE_KEY: Onyphe.io's API Key 

### Database configuration
Before running the project, you must populate the basic configuration for PostgreSQL.
In the project you can find a template file named `env_file_postgres_template`.
You have to create a new file named `env_file_postgres` from that template and modify it with your own configuration.

Required variables (we need to insert some of the values we have put in the previous configuration):
* POSTGRES_PASSWORD (same as DB_PASSWORD)
* POSTGRES_USER (same as DB_USER)
* POSTGRES_DB -> default `intel_owl_db`

If you prefer to use an external PostgreSQL instance, you should just remove the relative image from the `docker-compose.yml` file and provide the configuration to connect to your controlled instance/s.

### Web server configuration
By default Intel Owl provides basic configuration for:
* Nginx (`intel_owl_nginx_http` or `intel_owl_nginx_https`)
* Uwsgi (`intel_owl.ini`)

You can find them in the `configuration` directory.

By default, the project would use the default deployment configuration and HTTP only.

I suggest you to change these configuration files based on your needs and mount them as volumes by changing the `docker-compose.yml` file.

In case you enable HTTPS, remember to set the environment variable `HTTPS_ENABLED` as "enabled" to increment the security of the application.

### Analyzers configuration
In the file `analyzers_config.json` there is the configuration for all the available analyzers you can run.
For a complete list of all current available analyzer please look at: [Usage](./Usage.md)

You may want to change this configuration to add new analyzers or to change the configuration of some of them.

The name of the analyzers can be changed at every moment based on your wishes.
You just need to remember that it's important that you keep at least the following keys in the analyzers dictionaries to let them run correctly:
* `type`: can be `file` or `observable`. It specifies what the analyzer should analyze
* `python_module`: name of the task that the analyzer must launch

For a full description of the available keys, check the [Usage](./Usage.md) page

### Rebuilding the project
If you make some code changes and you like to rebuild the project, launch the following command from the project directory:

`docker build --tag=<your_tag> .`

Then, you should provide your own image in the `docker-compose.yml` file.


## AWS support
At the moment there's a basic support for some of the AWS services. More is coming in the future. 

### Secrets
If you would like to run this project on AWS, I'd suggest you to use the "Secrets Manager" to store your credentials. In this way your secrets would be better protected.

This project supports this kind of configuration. Instead of adding the variables to the environment file, you should just add them with the same name on the AWS Secrets Manager and Intel Owl will fetch them transparently.

Obviously, you should have created and managed the permissions in AWS in advance and accordingly to your infrastructure requirements.

Also, you need to set the environment variable `AWS_SECRETS` to `True` to enable this mode.

You can customize the AWS Region changing the environment variable `AWS_REGION`.

### SQS
If you like, you could use AWS SQS instead of Rabbit-MQ to manage your queues.
In that case, you should change the parameter `CELERY_BROKER_URL` to `sqs://` and give your instances on AWS the proper permissions to access it.

Also, you need to set the environment variable `AWS_SQS` to `True` to activate the additional required settings.

### ... More coming


## Run
After having properly configured the environment files as suggested previously, you can run the image.
The project uses `docker-compose`. You have to move to the project main directory to properly run it.

`docker-compose up`


## After deployment
### Users creation
You may want to run `docker exec -ti intel_owl_uwsgi python3 manage.py createsuperuser` after first run to create a superuser.
Then you can add other users directly from the Django Admin Interface after having logged with the superuser account.