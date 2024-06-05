# Installation

## Requirements
The project leverages `docker compose` with a custom Bash script and you need to have the following packages installed in your machine:
* [docker](https://docs.docker.com/get-docker/) - v19.03.0+
* [docker-compose](https://docs.docker.com/compose/install/) - v2.3.4+

In some systems you could find pre-installed older versions. Please check this and install a supported version before attempting the installation. Otherwise it would fail.
**Note:** We've added a new Bash script `initialize.sh` that will check compatibility with your system and attempt to install the required dependencies.

<div class="admonition note">
<p class="admonition-title">Note</p>
<ul>
<li>The project uses public docker images that are available on <a href="https://hub.docker.com/repository/docker/intelowlproject/intelowl">Docker Hub</a></li>
<li>IntelOwl is tested and supported to work in a Debian distro. More precisely we suggest using Ubuntu. Other Linux-based OS <i>should</i> work but that has not been tested much. It <i>may</i> also run on Windows, but that is not officially supported.</li>
<li>IntelOwl does not support ARM at the moment. We'll fix this with the next v6.0.5 release
<li>Before installing remember that you must comply with the <a href="https://github.com/certego/IntelOwl/blob/master/LICENSE">LICENSE</a> and the <a href="https://github.com/certego/IntelOwl/blob/master/.github/legal_notice.md">Legal Terms</a></li>
</ul>
</div>

<div class="admonition warning">
<p class="admonition-title">Warning</p>
The <code>start</code> script requires a `bash` version > 4 to run.

Note that macOS is shipped with an older version of <code>bash</code>. Please ensure to upgrade before running the script. 
</div>

## TL;DR
Obviously we strongly suggest reading through all the page to configure IntelOwl in the most appropriate way.

However, if you feel lazy, you could just install and test IntelOwl with the following steps. 
`docker` will be run with `sudo` if permissions/roles have not been set.

```bash
# clone the IntelOwl project repository
git clone https://github.com/intelowlproject/IntelOwl
cd IntelOwl/

# run helper script to verify installed dependencies and configure basic stuff
./initialize.sh

# start the app
./start prod up
# now the application is running on http://localhost:80

# create a super user 
sudo docker exec -ti intelowl_uwsgi python3 manage.py createsuperuser

# now you can login with the created user from http://localhost:80/login

# Have fun!
```

<div class="admonition warning">
<p class="admonition-title">Warning</p>
The first time you start IntelOwl, a lot of database migrations are being applied. This requires some time. If you get 500 status code errors in the GUI, just wait few minutes and then refresh the page.
</div>

[//]: # (<div class="admonition hint">)

[//]: # (<p class="admonition-title">Hint</p>)

[//]: # (There is a <a href="https://www.youtube.com/watch?v=GuEhqQJSQAs" target="_blank">YouTube video</a> that may help in the installation process. &#40;<i>ManySteps have changed since v2.0.0</i>&#41;)

[//]: # (</div>)

## Deployment Components
IntelOwl is composed of various different technologies, namely:
* React: Frontend, using [CRA](https://create-react-app.dev/) and [certego-ui](https://github.com/certego/certego-ui)
* Django: Backend
* PostgreSQL: Database
* Redis: Message Broker
* Celery: Task Queue
* Nginx: Reverse proxy for the Django API and web asssets.
* Uwsgi: Application Server
* Daphne: Asgi Server for WebSockets
* Elastic Search (*optional*): Auto-sync indexing of analysis' results.
* Kibana (*optional*): GUI for Elastic Search. We provide a saved configuration with dashboards and visualizations.
* Flower (*optional*): Celery Management Web Interface

All these components are managed via `docker compose`.

## Deployment Preparation

- [Environment configuration (required)](#environment-configuration-required)
- [Database configuration (required)](#database-configuration-required)
- [Web server configuration (optional)](#web-server-configuration-optional)
- [Analyzers configuration (optional)](#analyzers-or-connectors-configuration-optional)

Open a terminal and execute below commands to construct new environment files from provided templates.

```bash
./initialize.sh
```

### Environment configuration (required)
In the `docker/env_file_app`, configure different variables as explained below.

**REQUIRED** variables to run the image:
* `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`: PostgreSQL configuration (The DB credentals should match the ones in the `env_file_postgres`). If you like, you can configure the connection to an external PostgreSQL instance in the same variables. Then, to avoid to run PostgreSQL locally, please run IntelOwl with the option `--use-external-database`. Otherwise, `DB_HOST` must be `postgres` to have the app properly communicate with the PostgreSQL container.
* `DJANGO_SECRET`: random 50 chars key, must be unique. If you do not provide one, Intel Owl will automatically set a secret key and use the same for each run. The key is generated by `initialize.sh` script.

  **Strongly recommended** variable to set:
* `INTELOWL_WEB_CLIENT_DOMAIN` (example: `localhost`/`mywebsite.com`): the web domain of your instance, this is used for generating links to analysis results.

Optional configuration:
* `OLD_JOBS_RETENTION_DAYS`: Database retention for analysis results (default: 14 days). Change this if you want to keep your old analysis longer in the database.

#### Other optional configuration to enable specific services / features

Configuration required to enable integration with Slack:
* `SLACK_TOKEN`: Slack token of your Slack application that will be used to send/receive notifications
* `DEFAULT_SLACK_CHANNEL`: ID of the Slack channel you want to post the message to

Configuration required to enable Re-Captcha in the Login and the Registration Page:
In the `docker/env_file_app`:
* `USE_RECAPTCHA`: if you want to use recaptcha on your login
* `RECAPTCHA_SECRET_KEY`: your recaptcha secret key
In the `frontend/public/env.js`:
* `RECAPTCHA_SITEKEY`: Recaptcha Key for your site

Configuration required to have InteOwl sending Emails (registration requests, mail verification, password reset/change, etc)
* `DEFAULT_FROM_EMAIL`: email address used for automated correspondence from the site manager (example: `noreply@mydomain.com`)
* `DEFAULT_EMAIL`: email address used for correspondence with users (example: `info@mydomain.com`)
* `EMAIL_HOST`: the host to use for sending email with SMTP
* `EMAIL_HOST_USER`: username to use for the SMTP server defined in EMAIL_HOST
* `EMAIL_HOST_PASSWORD`: password to use for the SMTP server defined in EMAIL_HOST. This setting is used in conjunction with EMAIL_HOST_USER when authenticating to the SMTP server.
* `EMAIL_PORT`: port to use for the SMTP server defined in EMAIL_HOST.
* `EMAIL_USE_TLS`: whether to use an explicit TLS (secure) connection when talking to the SMTP server, generally used on port 587. 
* `EMAIL_USE_SSL`: whether to use an implicit TLS (secure) connection when talking to the SMTP server, generally used on port 465.

### Database configuration (required if running PostgreSQL locally)
If you use a local PostgreSQL instance (this is the default), in the `env_file_postgres` you have to configure different variables as explained below.

**Required** variables:
* `POSTGRES_PASSWORD` (same as `DB_PASSWORD`)
* `POSTGRES_USER` (same as `DB_USER`)
* `POSTGRES_DB` (default: `intel_owl_db`)

### Logrotate configuration (strongly recommended)
If you want to have your logs rotated correctly, we suggest you to add the configuration for the system Logrotate.
To do that you can leverage the `initialize.sh` script. Otherwise, if you have skipped that part, you can manually install logrotate by launching the following script:
```bash
cd ./docker/scripts
./install_logrotate.sh
```

We decided to do not leverage Django Rotation Configuration because it caused problematic concurrency issues, leading to logs that are not rotated correctly and to apps that do not log anymore.
Logrotate configuration is more stable.

### Crontab configuration (recommended for advanced deployments)
We added few Crontab configurations that could be installed in the host machine at system level to solve some possible edge-case issues:
* Memory leaks: Once a week it is suggested to do a full restart of the application to clean-up the memory used by the application. Practical experience suggest us to do that to solve some recurrent memory issues in Celery. A cron called `application_restart` has been added for this purpose (it uses the absolute path of `start` script in the container). This cron assumes that you have executed IntelOwl with the parameters `--all_analyzers`. If you didn't, feel free to change the cron as you wish.

This configuration is optional but strongly recommended for people who want to have a production grade deployment. To install it you need to run the following script in each deployed server:
```bash
cd ./docker/scripts
./install_crontab.sh
```

### Web server configuration (required for enabling HTTPS)
Intel Owl provides basic configuration for:
* Nginx (`configuration/nginx/http.conf`)
* Uwsgi (`configuration/intel_owl.ini`)

In case you enable HTTPS, remember to set the environment variable `HTTPS_ENABLED` as "enabled" to increment the security of the application.

There are 3 options to execute the web server:

- **HTTP only (default)**

    The project would use the default deployment configuration and HTTP only.

- **HTTPS with your own certificate**

    The project provides a template file to configure Nginx to serve HTTPS: `configuration/nginx/https.conf`.

    You should change `ssl_certificate`, `ssl_certificate_key` and `server_name` in that file and put those required files in the specified locations.

    Then you should call the `./start` script with the parameter `--https` to leverage the right Docker Compose file for HTTPS.
  
    Plus, if you use [Flower](Advanced-Configuration.html#queue-customization), you should change in the `docker/flower.override.yml` the `flower_http.conf` with `flower_https.conf`.

- **HTTPS with Let's Encrypt**

    We provide a specific docker-compose file that leverages [Traefik](https://docs.traefik.io/) to allow fast deployments of public-faced and HTTPS-enabled applications.

    Before using it, you should configure the configuration file `docker/traefik.override.yml` by changing the email address and the hostname where the application is served. For a detailed explanation follow the official documentation: [Traefix doc](https://docs.traefik.io/user-guides/docker-compose/acme-http/).
    
    After the configuration is done, you can add the option `--traefik` while executing [`./start`](#run)

## Run

<div class="admonition note">
<p class="admonition-title">Important Info</p>
IntelOwl depends heavily on docker and docker compose so as to hide this complexity from the enduser the project
leverages a custom shell script (<code>start</code>) to interface with <code>docker compose</code>.

You may invoke <code>$ ./start --help</code> to get help and usage info.

The CLI provides the primitives to correctly build, run or stop the containers for IntelOwl. Therefore,
<ul>
<li>It is possible to attach every optional docker container that IntelOwl has:
<a href="Advanced-Configuration.html#multi-queue"><em>multi_queue</em></a> with <em>traefik</em> enabled while every <a href="Advanced-Usage.html#optional-analyzers">optional docker analyzer</a> is active.</li> 
<li>It is possible to insert an optional docker argument that the CLI will pass to <code>docker-compose</code></li>
</ul>
</div>

Now that you have completed different configurations, starting the containers is as simple as invoking:

```bash
$ ./start prod up
```

You can add the `docker` options `-d` to run the application in the background. 
<div class="admonition note">
<p class="admonition-title">Important Info</p>
All <code>docker</code> and <code>docker compose</code> specific options must be passed at the end of the script, after a <code>--</code> token.
This token indicates the end of IntelOwl's options and the beginning of Docker options.

Example:
```bash
./start prod up -- -d
```
</div>


<div class="admonition hint">
<p class="admonition-title">Hint</p>
Starting from IntelOwl 4.0.0, with the startup script you can select which version of IntelOwl you want to run (<code>--version</code>).
This  can be helpful to keep using old versions in case of retrocompatibility issues. The <code>--version</code> parameter checks out the Git Repository to the Tag of the version that you have chosen. This means that if you checkout to a v3.x.x version, you won't have the <code>--version</code> parameter anymore so you would need to manually checkout back to the <code>master</code> branch to use newer versions.
</div>

### Stop
To stop the application you have to:
* if executed without `-d` parameter: press `CTRL+C` 
* if executed with `-d` parameter: `./start prod down`

### Cleanup of database and application
This is a destructive operation but can be useful to start again the project from scratch

`./start prod down -- -v`

## After Deployment

### Users creation
You may want to run `docker exec -ti intelowl_uwsgi python3 manage.py createsuperuser` after first run to create a superuser.
Then you can add other users directly from the Django Admin Interface after having logged with the superuser account.
To manage users, organizations and their visibility please refer to this [section](/Advanced-Usage.md#organizations-and-user-management)

## Update and Rebuild

### Rebuilding the project / Creating custom docker build
If you make some code changes and you like to rebuild the project, follow these steps:

1. `./start test build -- --tag=<your_tag> .` to build the new docker image.
2. Add this new image tag in the `docker/test.override.yml` file.
3. Start the containers with `./start test up -- --build`.

### Update to the most recent version
To update the project with the most recent available code you have to follow these steps:

```bash
$ cd <your_intel_owl_directory> # go into the project directory
$ git pull # pull new changes
$ ./start prod down # kill and destroy the currently running IntelOwl containers 
$ ./start prod up # restart the IntelOwl application
```

<div class="admonition warning">
<p class="admonition-title">Note</p>
After an upgrade, sometimes a database error in Celery Containers could happen. That could be related to new DB migrations which are not applied by the main Uwsgi Container yet. Do not worry. Wait few seconds for the Uwsgi container to start correctly, then put down the application again and restart it. The problem should be solved. If not, please feel free to open an issue on Github
</div>

<div class="admonition warning">
<p class="admonition-title">Note</p>
After having upgraded IntelOwl, in case the application does not start and you get an error like this:

```bash
PermissionError: [Errno 13] Permission denied: '/var/log/intel_owl/django/authentication.log
```

just run this:
```bash
sudo chown -R www-data:www-data /var/lib/docker/volumes/intel_owl_generic_logs/_data/django
```

and restart IntelOwl. It should solve the permissions problem.
</div>

<div class="admonition warning">
<p class="admonition-title">Warning</p>
Major versions of IntelOwl are usually incompatible from one another.
Maintainers strive to keep the upgrade between major version easy but it's not always like that.
Below you can find the additional process required to upgrade from each major versions.
</div>

#### Updating to >=6.0.0 from a 5.x.x version
IntelOwl v6 introduced some major changes regarding how the project is started.
Before upgrading, some important things should be checked by the administrator:
* Docker Compose V1 support has been dropped project-wide. If you are still using a Compose version prior to v2.3.4, please [upgrade](https://docs.docker.com/compose/migrate/) to a newer version or install Docker Compose V2.
* IntelOwl is now started with the new Bash `start` script that has the same options as the old Python `start.py` script but is more manageable and has decreased the overall project dependencies. The `start.py` script has now been removed. Please use the new `start` script instead.
* The default message broker is now Redis. We have replaced Rabbit-MQ for Redis to allow support for Websockets in the application:
  * This change is transparent if you use our `start` script to run IntelOwl. That would spawn a Redis instance instead of a Rabbit-MQ one locally.
  * If you were using an external broker like AWS SQS or a managed Rabbit-MQ, they are still supported but we suggest to move to a Redis supported service to simplify the architecture (because Redis is now mandatory for Websockets)
* Support for multiple jobs with multiple playbooks has been removed. Every Observable or File in the request will be processed by a single playbook. 
* We upgraded the base PostgreSQL image from version 12 to version 16. You have 2 choice:
  * remove your actual database and start from scratch with a new one
  * maintain your database and do not update Postgres. This could break the application at anytime because we do not support it anymore.
  * if you want to keep your old DB, follow the migration procedure you can find below

<div class="admonition warning">
<p class="admonition-title">Warning</p>
CARE! We are providing this database migration procedure to help the users to migrate to a new PostgreSQL version. 

Upgrading PostgreSQL is outside the scope of the IntelOwl project so we do not guarantee that everything will work as intended. 

In case of doubt, please check the official PostgreSQL documentation.

Upgrade at your own risk.
</div>

The database migration procedure is as follows:
- You have IntelOwl version 5.x.x up and running
- Bring down the application (you can use the start script or manually concatenate your docker compose configuration )
- Go inside the docker folder `cd docker`
- Bring only the postgres 12 container up `docker run -d --name intelowl_postgres_12 -v intel_owl_postgres_data:/var/lib/postgresql/data/ --env-file env_file_postgres  library/postgres:12-alpine`
- Dump the entire database. You need the user and the database that you configured during startup for this `docker exec -t intelowl_postgres_12  pg_dump -U <POSTGRES_USER> -d <POSTGRES_DB> --no-owner > /tmp/dump_intelowl.sql`
- Stop che container `docker container stop intelowl_postgres_12`
- Remove the backup container `docker container rm intelowl_postgres_12`
- Remove the postgres volume `docker volume rm intel_owl_postgres_data` <------------- remove old data, this is not exactly necessary because the new postgres has a different volume name
- Start the intermediary postgres 16 container `docker run -d --name intelowl_postgres_16 -v intelowl_postgres_data:/var/lib/postgresql/data/ --env-file env_file_postgres  library/postgres:16-alpine`
- Add the data to the volume `cat /tmp/dump_intelowl.sql | docker exec -i intelowl_postgres_16 psql -U <POSTGRES_USER> -d <POSTGRES_DB>`
- Stop the intermediary container `docker container stop intelowl_postgres_16`
- Remove the intermediary container `docker container rm intelowl_postgres_16`
- Update IntelOwl to the latest version
- Bring up the application back again (you can use the start script or manually concatenate your docker compose configuration)


#### Updating to >=5.0.0 from a 4.x.x version
IntelOwl v5 introduced some major changes regarding how the plugins and their related configuration are managed in the application.
Before upgrading, some important things should be checked by the administrator:
* A lot of database migrations will need to be applied. Just be patient few minutes once you install the new major release. If you get 500 status code errors in the GUI, just wait few minutes and then refresh the page.
* We moved away from the old big `analyzer_config.json` which was storing all the base configuration of the Analyzers to a database model (we did the same for all the other plugins types too). This allows us to manage plugins creation/modification/deletion in a more reliable manner and via the Django Admin Interface. If you have created custom plugins and changed those `<plugins>_config.json` file manually, you would need to re-create those custom plugins again from the Django Admin Interface. To do that please follow the [related new documentation](https://intelowl.readthedocs.io/en/develop/Usage.html#analyzers-customization)
* We have REMOVED all the analyzers that we deprecated during the v4 releases cycle. Please substitute them with their respective new names, in case they have a replacement.
  * REMOVED `Pulsedive_Active_IOC` analyzer. Please substitute it with the new `Pulsedive` analyzer.
  * REMOVED `Fortiguard` analyzer because endpoint does not work anymore. No substitute.
  * REMOVED `Rendertron` analyzer not working as intended. No substitute.
  * REMOVED `ThreatMiner`, `SecurityTrails` and `Robtex` various analyzers and substituted with new versions.
  * REMOVED `Doc_Info_Experimental`. Its functionality (XLM Macro parsing) is moved to `Doc_Info`
  * REMOVED `Strings_Info_Classic`. Please use `Strings_Info`
  * REMOVED `Strings_Info_ML`. Please use `Strings_Info` and set the parameter `rank_strings` to `True`
  * REMOVED all `Yara_Scan_<repo>` analyzers. They all went merged in the single `Yara` analyzer
  * REMOVED `Darksearch_Query` analyzer because the service does not exist anymore. No substitute.
  * REMOVED `UnpacMe_EXE_Unpacker`. Please use `UnpacMe`
  * REMOVED `BoxJS_Scan_JavaScript`. Please use `BoxJS`
  * REMOVED all `Anomali_Threatstream_<option>` analyzers. Now we have a single `Anomali_Threatstream` analyzer. Use the parameters to select the specific API you need.

#### Updating to >=5.0.0 from a 3.x.x version
This is not supported. Please perform a major upgrade once at a time.

#### Updating to >=4.0.0 from a 3.x.x version
IntelOwl v4 introduced some major changes regarding the permission management, allowing an easier way to manage users and visibility. But that did break the previous available DB.
So, to migrate to the new major version you would need to delete your DB. To do that, you would need to delete your volumes and start the application from scratch.
```bash
python3 start.py prod down -v
```
Please be aware that, while this can be an important effort to manage, the v4 IntelOwl provides an easier way to add, invite and manage users from the application itself. See [the Organization section](./Advanced-Usage.md#organizations-and-user-management).


#### Updating to >=2.0.0 from a 1.x.x version
Users upgrading from previous versions need to manually move `env_file_app`, `env_file_postgres` and `env_file_integrations` files under the new `docker` directory.

#### Updating to >v1.3.x from any prior version

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
