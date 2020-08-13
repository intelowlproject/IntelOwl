# Installation

## TL;DR
Obviously we strongly suggest to read through all the page to configure IntelOwl in the most appropriate way.

However, if you feel lazy, you could just install and test IntelOwl with the following steps.


```
git clone https://github.com/intelowlproject/IntelOwl
cd IntelOwl

# copy env files
cp env_file_postgres_template env_file_postgres
cp env_file_app_template env_file_app

# (optional) edit env files before starting the app to configure some analyzers
# see "Deployment preparation" paragraph below

# (optional) enable all docker-based analyzers
cp env_file_app_integrations_template env_file_app_integrations
cp .env_template .env
# in .env file comment line 10 and uncomment line 13

# start the app
docker-compose up -d

# create a super user 
docker exec -ti intel_owl_uwsgi python3 manage.py createsuperuser

# now the app is running on localhost:80
```

## Deployment
The project leverages docker-compose for a classic server deployment. So, you need [docker](https://docs.docker.com/get-docker/) and [docker-compose](https://docs.docker.com/compose/install/) installed in your machine.

Then, we suggest you to clone the project, configure the required environment variables and run `docker-compose up` using the docker-compose file that is embedded in the project.

That file leverages a public docker image that is available in [Docker Hub](https://hub.docker.com/repository/docker/intelowlproject/intelowl)

## Deployment Info
Main components of the web application:
* Angular: Frontend ([IntelOwl-ng](https://github.com/intelowlproject/IntelOwl-ng))
* Django: Backend
* PostgreSQL: Database
* Rabbit-MQ: Message Broker
* Celery: Task Queue
* Nginx: Web Server
* Uwsgi: Application Server
* Elastic Search (optional): Auto-sync indexing of analysis' results.
* Kibana (optional): GUI for Elastic Search. We provide a saved configuration with dashboards and visualizations.
* Flower (optional): Celery Management Web Interface

All these components are managed by docker-compose

## Deployment preparation
### Environment configuration (required)
Before running the project, you must populate some environment variables in a file to provide the required configuration.
In the project you can find a template file named `env_file_app_template`.
You have to create a new file named `env_file_app` from that template and modify it with your own configuration.

REQUIRED variables to run the image:
* DB_HOST, DB_PORT, DB_USER, DB_PASSWORD: PostgreSQL configuration

Strongly recommended variable to set:
* DJANGO_SECRET: random 50 chars key, must be unique. If you do not provide one, Intel Owl will automatically set a new secret on every run.

Optional variables needed to enable specific analyzers:
* ABUSEIPDB_KEY: AbuseIPDB API key
* AUTH0_KEY: Auth0 API Key
* SECURITYTRAILS_KEY: Securitytrails API Key
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
* MISP_KEY: your own MISP instance key
* MISP_URL your own MISP instance URL
* CUCKOO_URL: your cuckoo instance URL
* HONEYDB_API_ID & HONEYDB_API_KEY: HoneyDB API credentials
* CENSYS_API_ID & CENSYS_API_SECRET: Censys credentials
* ONYPHE_KEY: Onyphe.io's API Key 
* GREYNOISE_API_KEY: GreyNoise API ([docs](https://docs.greynoise.io))

Advanced additional configuration:
* OLD_JOBS_RETENTION_DAYS: Database retention, default 3 days. Change this if you want to keep your old analysis longer in the database.
* PYINTELOWL_TOKEN_LIFETIME: Token Lifetime for requests coming from the [PyIntelOwl](https://github.com/intelowlproject/pyintelowl) library, default to 7 days. It will expire only if unused. Increment this if you plan to use these tokens rarely.

### Database configuration (required)
Before running the project, you must populate the basic configuration for PostgreSQL.
In the project you can find a template file named `env_file_postgres_template`.
You have to create a new file named `env_file_postgres` from that template and modify it with your own configuration.

Required variables (we need to insert some of the values we have put in the previous configuration):
* POSTGRES_PASSWORD (same as DB_PASSWORD)
* POSTGRES_USER (same as DB_USER)
* POSTGRES_DB -> default `intel_owl_db`

If you prefer to use an external PostgreSQL instance, you should just remove the relative image from the `docker-compose.yml` file and provide the configuration to connect to your controlled instance/s.

### Web server configuration (optional)
Intel Owl provides basic configuration for:
* Nginx (`intel_owl_nginx_http`)
* Uwsgi (`intel_owl.ini`)

You can find them in the `configuration` directory.

In case you enable HTTPS, remember to set the environment variable `HTTPS_ENABLED` as "enabled" to increment the security of the application.

There are 3 options to execute the web server:

##### HTTP only (default)
The project would use the default deployment configuration and HTTP only.

##### HTTPS with your own certificate
The project provides a template file to configure Nginx to serve HTTPS: `intel_owl_nginx_https`.

You should change `ssl_certificate`, `ssl_certificate_key` and `server_name` in that file.

Then you should modify the `nginx` service configuration in `docker-compose.yml`:
* change `intel_owl_nginx_http` with `intel_owl_nginx_https`
* in `volumes` add the option for mounting the directory that hosts your certificate and your certificate key.


##### HTTPS with Let's Encrypt
We provide a specific docker-compose file that leverages [Traefik](https://docs.traefik.io/) to allow fast deployments of public-faced and HTTPS-enabled applications.

Before using it, you should configure the configuration file `docker-compose-with-traefik.yml` by changing the email address and the hostname where the application is served. For a detailed explanation follow the official documentation: [Traefix doc](https://docs.traefik.io/user-guides/docker-compose/acme-http/).
 
After the configuration is done, you should run docker-compose in this way:
`docker-compose -f docker-compose-with-traefik.yml up`


### Analyzers configuration (optional)
In the file `analyzers_config.json` there is the configuration for all the available analyzers you can run.
For a complete list of all current available analyzer please look at: [Usage](./Usage.md)

You may want to change this configuration to add new analyzers or to change the configuration of some of them.

The name of the analyzers can be changed at every moment based on your wishes.
You just need to remember that it's important that you keep at least the following keys in the analyzers dictionaries to let them run correctly:
* `type`: can be `file` or `observable`. It specifies what the analyzer should analyze
* `python_module`: name of the task that the analyzer must launch

For a full description of the available keys, check the [Usage](./Usage.md) page

> Some analyzers are kept optional and can easily be enabled. Refer to [this](https://intelowl.readthedocs.io/en/stable/Advanced-Usage.html#optional-analyzers) part of the docs.

#### Authentication options
IntelOwl provides support for some of the most common authentication methods:
* LDAP
* GSuite (work in progress)
##### LDAP
IntelOwl leverages [Django-auth-ldap](https://github.com/django-auth-ldap/django-auth-ldap
) to perform authentication via LDAP.

How to configure and enable LDAP on Intel Owl?

Inside the `settings` directory you can find a file called `ldap_config_template.py`. This file provides an example of configuration.
Copy that file into the same directory with the name `ldap_config.py`.
Then change the values with your LDAP configuration.

For more details on how to configure this file, check the [official documentation](https://django-auth-ldap.readthedocs.io/en/latest/) of the django-auth-ldap library.

Once you have done that, you have to set the environment variable `LDAP_ENABLED` as `True` in the environment configuration file `env_file_app`.
Finally, you can restart the application. 


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

`docker-compose up -d`


## After deployment

### Users creation
You may want to run `docker exec -ti intel_owl_uwsgi python3 manage.py createsuperuser` after first run to create a superuser.
Then you can add other users directly from the Django Admin Interface after having logged with the superuser account.

> For Django Groups & Permissions settings, refer [here](https://intelowl.readthedocs.io/en/stable/Advanced-Usage.html#django-groups-&-permissions).

## Update to the most recent version
To update the project with the most recent available code you have to follow these steps:

```bash
docker pull intelowlproject/intelowl_ng:latest  -> updates the webclient
cd <your_intel_owl_directory> && git pull   -> updates the project
docker-compose down && docker-compose up -d   -> restart the IntelOwl application
```