# Advanced Configuration

This page includes details about some advanced features that Intel Owl provides which can be **optionally** configured by the administrator.

  - [ElasticSearch](#elastic-search)
    - [Kibana](#kibana)
    - [Example Configuration](#example-configuration)
  - [Authentication options](#authentication-options)
    - [OAuth support](#google-oauth2)
    - [LDAP](#ldap)
    - [RADIUS](#radius-authentication)
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

## ElasticSearch

Intel Owl makes use of [django-elasticsearch-dsl](https://django-elasticsearch-dsl.readthedocs.io/en/latest/about.html) to index Job results into elasticsearch. The `save` and `delete` operations are auto-synced so you always have the latest data in ES.

In the `env_file_app_template`, you'd see various elasticsearch related environment variables. The user should spin their own Elastic Search instance and configure these variables.

#### Kibana

Intel Owl provides a Kibana's "Saved Object" configuration (with example dashboard and visualizations). It can be downloaded from [here](https://github.com/intelowlproject/IntelOwl/blob/develop/configuration/Kibana-Saved-Conf.ndjson) and can be imported into Kibana by going to the "Saved Objects" panel (http://localhost:5601/app/management/kibana/objects).

#### Example Configuration

1. Setup [Elastic Search and Kibana](https://hub.docker.com/r/nshou/elasticsearch-kibana/) and say it is running in a docker service with name `elasticsearch` on port `9200` which is exposed to the shared docker network.
   (Alternatively, you can spin up a local Elastic Search instance, by appending `--elastic` to the `python3 start.py ...` command. Note that the local Elastic Search instance consumes large amount of memory, and hence having >=16GB is recommended.))
2. In the `env_file_app`, we set `ELASTICSEARCH_ENABLED` to `True` and `ELASTICSEARCH_HOST` to `elasticsearch:9200`.
3. In the `Dockerfile`, set the correct version in `ELASTICSEARCH_DSL_VERSION` [depending on the version](https://django-elasticsearch-dsl.readthedocs.io/en/latest/about.html#features) of our elasticsearch server.
4. Rebuild the docker images with `docker-compose build` (required only if `ELASTICSEARCH_DSL_VERSION` was changed)
5. Now start the docker containers and execute,

```bash
docker exec -ti intelowl_uwsgi python manage.py search_index --rebuild
```

This will build and populate all existing job objects into the `jobs` index.

## Authentication options

IntelOwl provides support for some of the most common authentication methods:

- [Google Oauth2](#google-oauth2)
- [LDAP](#ldap)
- [RADIUS](#radius-authentication)

#### Google OAuth2

The first step is to create a [Google Cloud Platform](https://cloud.google.com/resource-manager/docs/creating-managing-projects) project, and then [create OAuth credentials for it](https://developers.google.com/workspace/guides/create-credentials#oauth-client-id).

After that, specify the client ID and secret as `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` environment variables.


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


## Cloud Support

### AWS support

We have support for several AWS services.

You can customize the AWS Region location of you services by changing the environment variable `AWS_REGION`. Default is `eu-central-1`

#### S3

If you prefer to use S3 to store the analyzed samples, instead of the local storage, you can do it.

First, you need to configure the environment variable `LOCAL_STORAGE` to `False` to enable it and set `AWS_STORAGE_BUCKET_NAME` to the proper AWS bucket.

Then you have to add some credentials for AWS: if you have IntelOwl deployed on the AWS infrastructure, you can use IAM credentials:
to allow that just set `AWS_IAM_ACCESS` to `True`. If that is not the case, you have to set both `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`

#### SQS

If you like, you could use AWS SQS instead of Rabbit-MQ to manage your queues.
In that case, you should change the parameter `BROKER_URL` to `sqs://` and give your instances on AWS the proper permissions to access it.

Also, you need to set the environment variable `AWS_SQS` to `True` to activate the additional required settings.

Ultimately, to avoid to run RabbitMQ locally, you would need to use the option `--use-external-broker` when launching IntelOwl with the `start.py` script.

#### SES

If you like, you could use Amazon SES for sending automated emails.

First, you need to configure the environment variable `AWS_SES` to `True` to enable it.
Then you have to add some credentials for AWS: if you have IntelOwl deployed on the AWS infrastructure, you can use IAM credentials:
to allow that just set `AWS_IAM_ACCESS` to `True`. If that is not the case, you have to set both `AWS_ACESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`.
Additionally, if you are not using the default AWS region of us-east-1, you need to specify your `AWS_REGION`

#### RDS

If you like, you could use AWS RDS instead of PostgreSQL for your database. In that case, you should change the database required options accordingly: `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD` and setup your machine to access the service.

If you have IntelOwl deployed on the AWS infrastructure, you can use IAM credentials to access the Postgres DB.
To allow that just set `AWS_RDS_IAM_ROLE` to `True`. In this case `DB_PASSWORD` is not required anymore.

Moreover, to avoid to run PostgreSQL locally, you would need to use the option `--use-external-database` when launching IntelOwl with the `start.py` script.

#### Secrets

You can use the "Secrets Manager" to store your credentials. In this way your secrets would be better protected.

Instead of adding the variables to the environment file, you should just add them with the same name on the AWS Secrets Manager and Intel Owl will fetch them transparently.

Obviously, you should have created and managed the permissions in AWS in advance and accordingly to your infrastructure requirements.

Also, you need to set the environment variable `AWS_SECRETS` to `True` to enable this mode.

### Google Kubernetes Engine

Right now there is no official support for Kubernetes deployments.

But we have an active community. Please refer to the following blog post for an example on how to deploy IntelOwl on Google Kubernetes Engine:

[Deploying Intel-Owl on GKE](https://mostwanted002.cf/post/intel-owl-gke/) by [Mayank Malik](https://twitter.com/_mostwanted002_).

## Queues

#### Multi Queue

IntelOwl provides an additional [multi-queue.override.yml](https://github.com/intelowlproject/IntelOwl/blob/master/docker/multi-queue.override.yml) compose file allowing IntelOwl users to better scale with the performance of their own architecture.

If you want to leverage it, you should add the option `--multi-queue` when starting the project. Example:

```bash
python3 start.py prod --multi-queue up
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
python3 start.py prod --flower up
```

The flower interface is available at port 5555: to set the credentials for its access, update the environment variables

```bash
FLOWER_USER
FLOWER_PWD
```

or change the `.htpasswd` file that is created in the `docker` directory in the `intelowl_flower` container.

