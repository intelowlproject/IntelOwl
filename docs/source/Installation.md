# Installation

## TL;DR
Obviously we strongly suggest to read through all the page to configure IntelOwl in the most appropriate way.

However, if you feel lazy, you could just install and test IntelOwl with the following steps.

```bash
# clone the IntelOwl project repository
git clone https://github.com/intelowlproject/IntelOwl
cd IntelOwl/

# construct environment files from templates
cd docker/
cp env_file_app_template env_file_app
cp env_file_postgres_template env_file_postgres
cp env_file_integrations_template env_file_integrations

# start the app
cd ..
python start.py prod up

# create a super user 
docker exec -ti intelowl_uwsgi python3 manage.py createsuperuser

# now the app is running on http://localhost:80
```

<div class="admonition hint">
<p class="admonition-title">Hint</p>
There is a <a href="https://www.youtube.com/watch?v=GuEhqQJSQAs" target="_blank">YouTube video</a> that may help in the installation process. (<i>ManySteps have changed since v2.0.0</i>)
</div>

## Requirements
The project leverages `docker-compose` with a custom python script so you need to have the following packages installed in your machine:
* [docker](https://docs.docker.com/get-docker/) - v1.13.0+
* [docker-compose](https://docs.docker.com/compose/install/) - v1.23.2+
* [python](https://www.python.org/) - v3.6+

<div class="admonition note">
<p class="admonition-title">Note</p>
<ul>
<li>The project uses public docker image that is available on <a href="https://hub.docker.com/repository/docker/intelowlproject/intelowl">Docker Hub</a></li>
<li>IntelOwl is tested and supported to work in a Linux-based OS. It <i>may</i> also run on windows, but that is not officialy supported yet.</li>
</ul>
</div>

## Deployment Components
IntelOwl is composed of various different services, namely:
* Angular: Frontend ([IntelOwl-ng](https://github.com/intelowlproject/IntelOwl-ng))
* Django: Backend
* PostgreSQL: Database
* Rabbit-MQ: Message Broker
* Celery: Task Queue
* Nginx: Reverse proxy for the Django API and web asssets.
* Uwsgi: Application Server
* Elastic Search (*optional*): Auto-sync indexing of analysis' results.
* Kibana (*optional*): GUI for Elastic Search. We provide a saved configuration with dashboards and visualizations.
* Flower (*optional*): Celery Management Web Interface

All these components are managed via docker-compose.

## Deployment Preparation

- [Environment configuration (required)](#environment-configuration-required)
- [Database configuration (required)](#database-configuration-required)
- [Web server configuration (optional)](#web-server-configuration-optional)
- [Analyzers configuration (optional)](#analyzers-configuration-optional)

Open a terminal and execute below commands to construct new environment files from provided templates.

```bash
cd docker/
cp env_file_app_template env_file_app
cp env_file_postgres_template env_file_postgres
cp env_file_integrations_template env_file_integrations
```

### Environment configuration (required)
In the `env_file_app`, configure different variables as explained below.

**REQUIRED** variables to run the image:
* `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`: PostgreSQL configuration (The DB credentals should match the ones in the `env_file_postgres`).

**Strongly recommended** variable to set:
* `DJANGO_SECRET`: random 50 chars key, must be unique. If you do not provide one, Intel Owl will automatically set a new secret on every run.

**Optional** variables needed to enable specific analyzers:
* `ABUSEIPDB_KEY`: AbuseIPDB API key
* `AUTH0_KEY`: Auth0 API Key
* `SECURITYTRAILS_KEY`: Securitytrails API Key
* `SHODAN_KEY`: Shodan API key
* `HUNTER_API_KEY`: Hunter.io API key
* `GSF_KEY`: Google Safe Browsing API key
* `OTX_KEY`: Alienvault OTX API key
* `CIRCL_CREDENTIALS`: CIRCL PDNS credentials in the format: `user|pass`
* `VT_KEY`: VirusTotal API key
* `HA_KEY`: HybridAnalysis API key
* `INTEZER_KEY`: Intezer API key
* `INQUEST_API_KEY`: InQuest API key
* `FIRST_MISP_API`: FIRST MISP API key
* `FIRST_MISP_URL`: FIRST MISP URL
* `MISP_KEY`: your own MISP instance key
* `MISP_URL`: your own MISP instance URL
* `DNSDB_KEY`: DNSDB API key
* `CUCKOO_URL`: your cuckoo instance URL
* `HONEYDB_API_ID` & `HONEYDB_API_KEY`: HoneyDB API credentials
* `CENSYS_API_ID` & `CENSYS_API_SECRET`: Censys credentials
* `ONYPHE_KEY`: Onyphe.io's API Key 
* `GREYNOISE_API_KEY`: GreyNoise API ([docs](https://docs.greynoise.io))
* `INTELX_API_KEY`: IntelligenceX API ([docs](https://intelx.io/product))
* `UNPAC_ME_API_KEY`: UnpacMe API ([docs](https://api.unpac.me/))
* `IPINFO_KEY`: ipinfo API key
* `ZOOMEYE_KEY`: ZoomEye API Key([docs](https://www.zoomeye.org/doc))
* `TRIAGE_KEY`: tria.ge API key([docs](https://tria.ge/docs/))
* `WIGLE_KEY`: WiGLE API Key([docs](https://api.wigle.net/))

**Advanced** additional configuration:
* `OLD_JOBS_RETENTION_DAYS`: Database retention for analysis results (default: 3 days). Change this if you want to keep your old analysis longer in the database.

### Database configuration (required)
In the `env_file_postgres`, configure different variables as explained below.

**Required** variables:
* `POSTGRES_PASSWORD` (same as `DB_PASSWORD`)
* `POSTGRES_USER` (same as `DB_USER`)
* `POSTGRES_DB` (default: `intel_owl_db`)

If you prefer to use an external PostgreSQL instance, you should just remove the relative image from the `docker/default.yml` file and provide the configuration to connect to your controlled instances.

### Web server configuration (optional)
Intel Owl provides basic configuration for:
* Nginx (`configuration/intel_owl_nginx_http`)
* Uwsgi (`configuration/intel_owl.ini`)

In case you enable HTTPS, remember to set the environment variable `HTTPS_ENABLED` as "enabled" to increment the security of the application.

There are 3 options to execute the web server:

- **HTTP only (default)**

    The project would use the default deployment configuration and HTTP only.

- **HTTPS with your own certificate**

    The project provides a template file to configure Nginx to serve HTTPS: `configuration/intel_owl_nginx_https`.

    You should change `ssl_certificate`, `ssl_certificate_key` and `server_name` in that file.

    Then you should modify the `nginx` service configuration in `docker/default.yml`:
    * change `intel_owl_nginx_http` with `intel_owl_nginx_https`
    * in `volumes` add the option for mounting the directory that hosts your certificate and your certificate key.

- **HTTPS with Let's Encrypt**

    We provide a specific docker-compose file that leverages [Traefik](https://docs.traefik.io/) to allow fast deployments of public-faced and HTTPS-enabled applications.

    Before using it, you should configure the configuration file `docker/traefik.override.yml` by changing the email address and the hostname where the application is served. For a detailed explanation follow the official documentation: [Traefix doc](https://docs.traefik.io/user-guides/docker-compose/acme-http/).
    
    After the configuration is done, you can add the option `--traefik` while executing the [`start.py`](#run)


### Analyzers configuration (optional)
In the file `configuration/analyzers_config.json` there is the configuration for all the available analyzers you can run.
For a complete list of all current available analyzer please look at: [Usage](./Usage.md)

You may want to change this configuration to add new analyzers or to change the configuration of some of them.

The name of the analyzers can be changed at every moment based on your wishes.
You just need to remember that it's important that you keep at least the following keys in the analyzers dictionaries to let them run correctly:
* `type`: can be `file` or `observable`. It specifies what the analyzer should analyze
* `python_module`: path to the analyzer class


<div class="admonition hint">
<p class="admonition-title">Hint</p>
You can see the full list of all available analyzers in the <a href="Usage.html#available-analyzers">Usage.html</a> or <a href="https://intelowlclient.firebaseapp.com/pages/analyzers/table">Live Demo</a>.
</div>

<div class="admonition hint">
<p class="admonition-title">Hint</p>
Some analyzers are kept optional and can easily be enabled. Refer to <a href="Advanced-Usage.html#optional-analyzers">this</a> part of the docs.
</div>

## AWS support
At the moment there's a basic support for some of the AWS services. More is coming in the future. 

#### Secrets
If you would like to run this project on AWS, I'd suggest you to use the "Secrets Manager" to store your credentials. In this way your secrets would be better protected.

This project supports this kind of configuration. Instead of adding the variables to the environment file, you should just add them with the same name on the AWS Secrets Manager and Intel Owl will fetch them transparently.

Obviously, you should have created and managed the permissions in AWS in advance and accordingly to your infrastructure requirements.

Also, you need to set the environment variable `AWS_SECRETS` to `True` to enable this mode.

You can customize the AWS Region changing the environment variable `AWS_REGION`.

#### SQS
If you like, you could use AWS SQS instead of Rabbit-MQ to manage your queues.
In that case, you should change the parameter `CELERY_BROKER_URL` to `sqs://` and give your instances on AWS the proper permissions to access it.

Also, you need to set the environment variable `AWS_SQS` to `True` to activate the additional required settings.

#### ... More coming


## Run

<div class="admonition note">
<p class="admonition-title">Important Info</p>
IntelOwl depends heavily on docker and docker compose so as to hide this complexity from the enduser the project
leverages a custom script (<code>start.py</code>) to interface with <code>docker-compose</code>.

You may invoke <code>$ python3 start.py --help</code> to get help and usage info.

The CLI provides the primitives to correctly build, run or stop the containers for IntelOwl. Therefore,
<ul>
<li>It is possible to attach every optional docker container that IntelOwl has:
<a href="Advanced-Usage.html#multi-queue"><em>multi_queue</em></a> with <em>traefik</em> enabled while every <a href="Advanced-Usage.html#optional-analyzers">optional docker analyzer</a> is active.</li> 
<li>It is possible to insert an optional docker argument that the CLI will pass to <code>docker-compose</code></li>
</ul>
</div>




Now that you have completed different configurations, starting the containers is as simple as invoking:

```bash
$ python start.py prod up
```

## After Deployment

### Users creation
You may want to run `docker exec -ti intelowl_uwsgi python3 manage.py createsuperuser` after first run to create a superuser.
Then you can add other users directly from the Django Admin Interface after having logged with the superuser account.

### Django Groups & Permissions settings

Refer to [this](./Advanced-Usage.html#django-groups-permissions) section of the docs.

## Extras

### Deploy on Remnux
[Remnux](https://remnux.org/) is a Linux Toolkit for Malware Analysis.

IntelOwl and Remnux have the same goal: save the time of people who need to perform malware analysis or info gathering.

Therefore we suggest [Remnux](https://docs.remnux.org/) users to install IntelOwl to leverage all the tools provided by both projects in a unique environment.

To do that, you can follow the same steps detailed [above](https://intelowl.readthedocs.io/en/latest/Installation.html#tl-dr) for the installation of IntelOwl.

### Update to the most recent version
To update the project with the most recent available code you have to follow these steps:

```bash
$ cd <your_intel_owl_directory> # go into the project directory
$ git pull # pull new changes
$ python start.py prod stop # kill the currently running IntelOwl containers 
$ python start.py prod up --build # restart the IntelOwl application
```

### Rebuilding the project/ Creating custom docker build
If you make some code changes and you like to rebuild the project, follow these steps:

1. `python start.py test build --tag=<your_tag> .` to build the new docker image.
2. Add this new image tag in the `docker/test.override.yml` file.
3. Start the containers with `python start.py test up --build`.

### Updating to >=2.0.0 from a 1.x.x version
Users upgrading from previous versions need to manually move `env_file_app`, `env_file_postgres` and `env_file_integrations` files under the new `docker` directory.

### Updating to >v1.3.x from any prior version

If you are updating to >[v1.3.0](https://github.com/intelowlproject/IntelOwl/releases/tag/v1.3.0) from any prior version, you need to execute a helper script so that the old data present in the database doesn't break.

1. Follow the above updation steps, once the docker containers are up and running execute the following in a new terminal

    ```bash
    docker exec -ti intelowl_uwsgi bash
    ```

    to get a shell session inside the IntelOwl's container.

2. Now just copy and paste the below command into this new session,

    ```bash
    curl https://gist.githubusercontent.com/Eshaan7/b111f887fa8b860c762aa38d99ec5482/raw/758517acf87f9b45bd22f06aee57251b1f3b1bbf/update_to_v1.3.0.py | python -
    ```

3. If you see "Update successful!", everything went fine and now you can enjoy the new features!
