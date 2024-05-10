# Advanced Configuration

This page includes details about some advanced features that Intel Owl provides which can be **optionally** configured by the administrator.

  - [ElasticSearch](#elastic-search)
    - [Kibana](#kibana)
    - [Example Configuration](#example-configuration)
    - [Business Intelligence](#business-intelligence)
  - [Authentication options](#authentication-options)
    - [OAuth support](#google-oauth2)
    - [LDAP](#ldap)
    - [RADIUS](#radius-authentication)
  - [OpenCTI support](#opencti)
  - [Cloud Support](#cloud-support)
    - [AWS support](#aws-support)
      - [Secrets](#secrets)
      - [SQS](#sqs)
      - [S3](#s3)
      - [SES](#ses)
    - [Google Kubernetes Engine](#google-kubernetes-engine)
  - [Queues](#queues)
    - [Multi Queue](#multi-queue)
    - [Queue Customization](#queue-customization)
    - [Queue monitoring](#queue-monitoring)
  - [Manual usage](#manual-usage)

## ElasticSearch
Right now only ElasticSearch v8 is supported.

### DSL
IntelOwl makes use of [django-elasticsearch-dsl](https://django-elasticsearch-dsl.readthedocs.io/en/latest/about.html) to index Job results into elasticsearch. The `save` and `delete` operations are auto-synced so you always have the latest data in ES.

In the `env_file_app_template`, you'd see various elasticsearch related environment variables. The user should spin their own Elastic Search instance and configure these variables.

#### Kibana

Intel Owl provides a Kibana's "Saved Object" configuration (with example dashboard and visualizations). It can be downloaded from [here](https://github.com/intelowlproject/IntelOwl/blob/develop/configuration/Kibana-Saved-Conf.ndjson) and can be imported into Kibana by going to the "Saved Objects" panel (http://localhost:5601/app/management/kibana/objects).

#### Example Configuration

1. Setup [Elastic Search and Kibana](https://hub.docker.com/r/nshou/elasticsearch-kibana/) and say it is running in a docker service with name `elasticsearch` on port `9200` which is exposed to the shared docker network.
   (Alternatively, you can spin up a local Elastic Search instance, by appending `--elastic` to the `./start` command. Note that the local Elastic Search instance consumes large amount of memory, and hence having >=16GB is recommended.))
2. In the `env_file_app`, we set `ELASTICSEARCH_DSL_ENABLED` to `True` and `ELASTICSEARCH_DSL_HOST` to `elasticsearch:9200`.
3. Now start the docker containers and execute

```bash
docker exec -ti intelowl_uwsgi python manage.py search_index --rebuild
```

This will build and populate all existing job objects into the `jobs` index.


### Business Intelligence
IntelOwl makes use of [elasticsearch-py](https://elasticsearch-py.readthedocs.io/en/8.x/index.html) to store data that can be used for Business Intelligence purpose.
Since plugin reports are deleted periodically, this feature allows to save indefinitely small amount of data to keep track of how analyzers perform and user usage.
At the moment, the following information are sent to elastic:
- application name
- timestamp
- username
- configuration used
- process_time
- status
- end_time
- parameters

Documents are saved in the `ELEASTICSEARCH_BI_INDEX-%YEAR-%MONTH`, allowing to manage the retention accordingly.
To activate this feature, it is necessary to set `ELASTICSEARCH_BI_ENABLED` to `True` in the `env_file_app` and
`ELASTICSEARCH_BI_HOST` to `elasticsearch:9200`
or your elasticsearch server.

An [index template](https://github.com/intelowlproject/IntelOwl/configuration/elastic_search_mappings/intel_owl_bi.json) is created after the first bulk submission of reports. 
If you want to use kibana to visualize your data/make dashboard, you must create an index pattern:
Go to Kibana -> Discover -> Stack Management -> Index Patterns -> search for your index and use as time field `timestamp` 

## Authentication options

IntelOwl provides support for some of the most common authentication methods:

- [Google Oauth2](#google-oauth2)
- [LDAP](#ldap)
- [RADIUS](#radius-authentication)

#### Google OAuth2

The first step is to create a [Google Cloud Platform](https://cloud.google.com/resource-manager/docs/creating-managing-projects) project, and then [create OAuth credentials for it](https://developers.google.com/workspace/guides/create-credentials#oauth-client-id).

It is important to add the correct callback in the "Authorized redirect URIs" section to allow the application to redirect properly after the successful login. Add this:
```url
http://<localhost|yourowndomain>/api/auth/google-callback
```

After that, specify the client ID and secret as `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` environment variables and restart IntelOwl to see the applied changes.


<div class="admonition note">
<p class="admonition-title">Note</p>
While configuring Google Auth2 you can choose either to enable access to the all users with a Google Account ("External" mode) or to enable access to only the users of your organization ("Internal" mode).
<a href="https://support.google.com/cloud/answer/10311615#user-type&zippy=%2Cinternal%2Cexternal" target="_blank">Reference</a>
</div>

#### LDAP

IntelOwl leverages [Django-auth-ldap](https://github.com/django-auth-ldap/django-auth-ldap) to perform authentication via LDAP.

How to configure and enable LDAP on Intel Owl?

1. Change the values with your LDAP configuration inside `configuration/ldap_config.py`. This file is mounted as a docker volume, so you won't need to rebuild the image.

<div class="admonition note">
<p class="admonition-title">Note</p>
For more details on how to configure this file, check the <a href="https://django-auth-ldap.readthedocs.io/en/latest/" target="_blank">official documentation</a> of the django-auth-ldap library.
</div>

2. Once you have done that, you have to set the environment variable `LDAP_ENABLED` as `True` in the environment configuration file `env_file_app`.
   Finally, you can restart the application with `docker-compose up`

#### RADIUS Authentication

IntelOwl leverages [Django-radius](https://github.com/robgolding/django-radius) to perform authentication
via RADIUS server.

How to configure and enable RADIUS authentication on Intel Owl?

1. Change the values with your RADIUS auth configuration inside `configuration/radius_config.py`. This file is mounted as a
   docker volume, so you won't need to rebuild the image.

<div class="admonition note">
<p class="admonition-title">Note</p>
For more details on how to configure this file, check the <a href="https://github.com/robgolding/django-radius" target="_blank">official documentation</a> of the django-radius library.
</div>

2. Once you have done that, you have to set the environment variable `RADIUS_AUTH_ENABLED` as `True` in the environment
   configuration file `env_file_app`. Finally, you can restart the application with `docker-compose up`


## OpenCTI
Like many other integrations that we have, we have an [Analyzer](https://intelowl.readthedocs.io/en/latest/Usage.html#analyzers) and a [Connector](https://intelowl.readthedocs.io/en/latest/Usage.html#connectors) for the [OpenCTI]([OpenCTI](https://github.com/OpenCTI-Platform/opencti)) platform.

This allows the users to leverage these 2 popular open source projects and frameworks together.

So why we have a section here? This is because there are various compatibility problems with the [official PyCTI library](https://github.com/OpenCTI-Platform/client-python/).

We found out (see issues in [IntelOwl](https://github.com/intelowlproject/IntelOwl/issues/1730) and [PyCTI](https://github.com/OpenCTI-Platform/client-python/issues/287)) that, most of the times, it is required that the OpenCTI version of the server you are using and the pycti version installed in IntelOwl **must** match perfectly.

Because of that, we decided to provide to the users the chance to customize the version of PyCTI installed in IntelOwl based on the OpenCTI version that they are using.

To do that, you would need to leverage the option `--pycti-version` provided by the `./start` helper:
* check the default version that would be installed by checking the description of the option `--pycti-version` with `./start -h`
* if the default version is different from your OpenCTI server version, you need to rebuild the IntelOwl Image with `./start test build --pycti-version <your_version>`
* then restart the project `./start test up -- --build`
* enjoy

## Cloud Support

### AWS support

We have support for several AWS services.

You can customize the AWS Region location of you services by changing the environment variable `AWS_REGION`. Default is `eu-central-1`

You have to add some credentials for AWS: if you have IntelOwl deployed on the AWS infrastructure, you can use IAM credentials:
to allow that just set `AWS_IAM_ACCESS` to `True`. If that is not the case, you have to set both `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`

#### S3

If you prefer to use S3 to store the analyzed samples, instead of the local storage, you can do it.

First, you need to configure the environment variable `LOCAL_STORAGE` to `False` to enable it and set `AWS_STORAGE_BUCKET_NAME` to the AWS bucket you want to use.

Then you need to configure permission access to the chosen S3 bucket.


#### Message Broker

IntelOwl at the moment supports 3 different message brokers:
- Redis (default)
- RabbitMQ
- Aws SQS

The default broker, if nothing is specified, is `Redis`.

To use `RabbitMQ`, you must use the option `--rabbitmq` when launching IntelOwl with the `./start` script.

To use `Aws SQS`, you must use the option `--sqs` when launching IntelOwl with the `.start` script.
In that case, you should create new SQS queues in AWS called `intelowl-<environment>-<queue_name>` and give your instances on AWS the proper permissions to access it.
Moreover, you must populate the `AWS_USER_NUMBER`. This is required to connect in the right way to the selected SQS queues.
Only FIFO queues are supported.

If you want to use a remote message broker (like an `ElasticCache` or `AmazonMQ` instance), you must populate the `BROKER_URL` environment variable.

It is possible to use [task priority](https://docs.celeryq.dev/en/stable/userguide/routing.html#special-routing-options) inside IntelOwl: each User has default priority of 10, and robots users (like the Ingestors) have a priority of 7.    
You can customize these priorities inside Django Admin, in the `Authentication.User Profiles` section.

#### Websockets

`Redis` is used for two different functions:
- message broker
- websockets

For this reason, a `Redis` instance is **mandatory**.
You can personalize IntelOwl in two different way:
- with a local `Redis` instance.

This is the default behaviour.

- With a remote `Redis` instance.

You must use the option `--use-external-redis` when launching IntelOwl with the `.start` script.
Moreover, you need to populate the `WEBSOCKETS_URL` environment variable. If you are using `Redis` as a message broker too, remember to populate the `BROKER_URL` environment variable 

#### RDS

If you like, you could use AWS RDS instead of PostgreSQL for your database. In that case, you should change the database required options accordingly: `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD` and setup your machine to access the service.

If you have IntelOwl deployed on the AWS infrastructure, you can use IAM credentials to access the Postgres DB.
To allow that just set `AWS_RDS_IAM_ROLE` to `True`. In this case `DB_PASSWORD` is not required anymore.

Moreover, to avoid to run PostgreSQL locally, you would need to use the option `--use-external-database` when launching IntelOwl with the `./start` script.

#### SES

If you like, you could use Amazon SES for sending automated emails (password resets / registration requests, etc).

You need to configure the environment variable `AWS_SES` to `True` to enable it.

#### Secrets

You can use the "Secrets Manager" to store your credentials. In this way your secrets would be better protected.

Instead of adding the variables to the environment file, you should just add them with the same name on the AWS Secrets Manager and Intel Owl will fetch them transparently.

Obviously, you should have created and managed the permissions in AWS in advance and accordingly to your infrastructure requirements.

Also, you need to set the environment variable `AWS_SECRETS` to `True` to enable this mode.

#### NFS

You can use a `Network File System` for the shared_files that are downloaded runtime by IntelOwl (for example Yara rules).

To use this feature, you would need to add the address of the remote file system inside the `.env` file,
and you would need to use the option `--nfs` when launching IntelOwl with the `./start` script.

### Google Kubernetes Engine

Right now there is no official support for Kubernetes deployments.

But we have an active community. Please refer to the following blog post for an example on how to deploy IntelOwl on Google Kubernetes Engine:

[Deploying Intel-Owl on GKE](https://mostwanted002.cf/post/intel-owl-gke/) by [Mayank Malik](https://twitter.com/_mostwanted002_).

## Queues

#### Multi Queue

IntelOwl provides an additional [multi-queue.override.yml](https://github.com/intelowlproject/IntelOwl/blob/master/docker/multi-queue.override.yml) compose file allowing IntelOwl users to better scale with the performance of their own architecture.

If you want to leverage it, you should add the option `--multi-queue` when starting the project. Example:

```bash
./start prod up --multi-queue
```

This functionality is not enabled by default because this deployment would start 2 more containers so the resource consumption is higher. We suggest to use this option only when leveraging IntelOwl massively.

#### Queue Customization

It is possible to define new celery workers: each requires the addition of a new container in the docker-compose file, as shown in the `multi-queue.override.yml`.

Moreover IntelOwl requires that the name of the workers are provided in the `docker-compose` file. This is done through the environment variable `CELERY_QUEUES` inside the `uwsgi` container. Each queue must be separated using the character `,`, as shown in the [example](https://github.com/intelowlproject/IntelOwl/blob/master/docker/multi-queue.override.yml#L6).

One can customize what analyzer should use what queue by specifying so in the analyzer entry in the [analyzer_config.json](https://github.com/intelowlproject/IntelOwl/blob/master/configuration/analyzer_config.json) configuration file. If no queue(s) are provided, the `default` queue will be selected.

#### Queue monitoring

IntelOwl provides an additional [flower.override.yml](https://github.com/intelowlproject/IntelOwl/blob/master/docker/flower.override.yml) compose file allowing IntelOwl users to use [Flower](https://flower.readthedocs.io/) features to monitor and manage queues and tasks

If you want to leverage it, you should add the option `--flower` when starting the project. Example:

```bash
./start prod up --flower
```

The flower interface is available at port 5555: to set the credentials for its access, update the environment variables

```bash
FLOWER_USER
FLOWER_PWD
```

or change the `.htpasswd` file that is created in the `docker` directory in the `intelowl_flower` container.

## Manual Usage
The `./start` script essentially acts as a wrapper over Docker Compose, performing additional checks.
IntelOwl can still be started by using the standard `docker compose` command, but all the dependencies have to be manually installed by the user. 

### Options
The `--project-directory` and `-p` options are required to run the project.
Default values set by `./start` script are "docker" and "intel_owl", respectively.

The startup is based on [chaining](https://docs.docker.com/compose/multiple-compose-files/merge/) various Docker Compose YAML files using `-f` option. 
All Docker Compose files are stored in `docker/` directory of the project.
The default compose file, named `default.yml`, requires configuration for an external database and message broker.
In their absence, the `postgres.override.yml` and `rabbitmq.override.yml` files should be chained to the default one.

The command composed, considering what is said above (using `sudo`), is
```bash
sudo docker compose --project-directory docker -f docker/default.yml -f docker/postgres.override.yml -f docker/rabbitmq.override.yml -p intel_owl up
```

The other most common compose file that can be used is for the testing environment. 
The equivalent of running `./start test up` is adding the `test.override.yml` file, resulting in:
```bash
sudo docker compose --project-directory docker -f docker/default.yml -f docker/postgres.override.yml -f docker/rabbitmq.override.yml -f docker/test.override.yml -p intel_owl up
```

All other options available in the `./start` script (`./start -h` to view them) essentially chain other compose file to `docker compose` command with corresponding filenames.

### Optional Analyzer
IntelOwl includes integrations with [some analyzer](https://intelowl.readthedocs.io/en/latest/Advanced-Usage.html#optional-analyzers) that are not enabled by default.
These analyzers, stored under the `integrations/` directory, are packed within Docker Compose files.
The `compose.yml` file has to be chained to include the analyzer. 
The additional `compose-test.yml` file has to be chained for testing environment.