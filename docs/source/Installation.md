# Installation

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

#### Optional Analyzers
Some analyzers which run in their own Docker containers are kept disabled by default. They are disabled by default to prevent accidentally starting too many containers and making your computer unresponsive.

<style>
table, th, td {
  padding: 5px;
  border: 1px solid black;
  border-collapse: collapse;
}
</style>
<table style="width:100%">
  <tr>
    <th>Name</th>
    <th>Port</th>
    <th>Analyzers</th>
  </tr>
  <tr>
    <td>PEframe</td>
    <td>4000</td>
    <td><code>PEframe_Scan</code></td>
  </tr>
  <tr>
    <td>Thug</td>
    <td>4001</td>
    <td><code>Thug_URL_Info_*</code>, <code>Thug_HTML_Info_*</code></td>
  </tr>
  <tr>
    <td>FireEye Capa</td>
    <td>4002</td>
    <td><code>Capa_Info</code></td>
  </tr>
  <tr>
    <td>Box-JS</td>
    <td>4003</td>
    <td><code>BoxJS_Scan_JavaScript</code></td>
  </tr>
  <tr>
    <td>APK Analyzers</td>
    <td>4004</td>
    <td><code>APKiD_Scan_APK_DEX_JAR</code></td>
  </tr>
</table>

In the project, you can find template files named `.env_template` and `.env_file_integrations_template`.
You have to create new files named `.env` and `env_file_integrations` from these two templates.

Docker services defined in the compose files added in `COMPOSE_FILE` variable present in the `.env` file are ran on `docker-compose up`. So, modify it to include only the analyzers you wish to use.
Such compose files are available under `integrations/`.

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

### Django Groups & Permissions (Optional, Advanced Usage)
The application makes use of [Django's built-in permissions system](https://docs.djangoproject.com/en/3.0/topics/auth/default/#permissions-and-authorization). It provides a way to assign permissions to specific users and groups of users.

As an administrator here's what you need to know,
- Each user should belong to atleast a single group and permissions should be assigned to these groups. Please refrain from assigning user level permissions.
- When you create a first normal user, a group with name `DefaultGlobal` is created with all permissions granted. Every new user automatically gets added to this group.
   - This is done because most admins won't need to deal with user permissions and this way, they don't have to.
   - If you don't want a global group (with all permissions) but custom groups with custom permissions,
   just strip `DefaultGlobal` of all permissions but do *not* delete it.

The permissions work the way one would expect,
- `api_app | Job | view job` allows users to fetch list of all jobs he/she has permission for or a particular job with it's ID.
- `api_app | Job | create job` allows users to request new analysis. When user creates a job (requests new analysis),
    - the object level `view` permission is applied to all groups the requesting user belongs to or to all groups (depending on the parameters passed). 
    - the object level `change` and `delete` permission is restricted to superusers/admin.
- `api_app | Tag | create tag` allows users to create new tags. When user creates a new tag,
    - this new tag is visible (object level `view` permission) to each and every group but,
    - the object level `change` and `delete` permission is given to only those groups the requesting user belongs to. 
    - This is done because tag labels and colors are unique columns and the admin in most cases would want to define tags that are usable (but not modifiable) by users of all groups.
- `api_app | Tag | view tag` allows users to fetch list of all tags or a particular tag with it's ID.
- `api_app | Tag | change tag` allows users to edit a tag granted that user has the object level permission for the particular tag.