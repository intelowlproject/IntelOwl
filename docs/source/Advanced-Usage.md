# Advanced Usage

This page includes details about some advanced features that Intel Owl provides which can be optionally enabled. Namely,

- [Advanced Usage](#advanced-usage)
  - [Optional Analyzers](#optional-analyzers)
  - [Customize analyzer execution at time of request](#customize-analyzer-execution-at-time-of-request)
        - [View and understand different parameters](#view-and-understand-different-parameters)
        - [from the GUI](#from-the-gui)
        - [from Pyintelowl](#from-pyintelowl)
  - [Analyzers with special configuration](#analyzers-with-special-configuration)
  - [Elastic Search](#elastic-search)
      - [Kibana](#kibana)
      - [Example Configuration](#example-configuration)
  - [Django Groups & Permissions](#django-groups--permissions)
  - [Authentication options](#authentication-options)
      - [LDAP](#ldap)
  - [Google Kubernetes Engine deployment](#google-kubernetes-engine-deployment)
  - [Queues](#queues)
      - [Multi Queue](#multi-queue)
      - [Queue Customization](#queue-customization)
      - [Queue monitoring](#queue-monitoring)
  - [AWS support](#aws-support)
      - [Secrets](#secrets)
      - [SQS](#sqs)
      - [S3](#s3)


## Optional Analyzers
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
    <th>Analyzers</th>
    <th>Description</th>
  </tr>
  <tr>
    <td>Static Analyzers</td>
    <td><code>PEframe_Scan</code>, <code>Capa_Info</code>, <code>Floss</code>, <code>Strings_Info_Classic</code>, <code>Strings_Info_ML</code>, <code>Manalyze</code>, <code>ClamAV</code></td>
    <td>
    <ul>
      <li>Capa detects capabilities in executable files</li>
      <li>PEFrame performs static analysis on Portable Executable malware and malicious MS Office documents</li>
      <li>FLOSS automatically deobfuscate strings from malware binaries</li>
      <li>String_Info_Classic extracts human-readable strings where as ML version of it ranks them</li>
      <li>Manalyze statically analyzes PE (Portable-Executable) files in-depth</li>
      <li>ClamAV antivirus engine scans files for trojans, viruses, malwares using a multi-threaded daemon</li>
      </ul>
    </td>
  </tr>
  <tr>
    <td>Thug</td>
    <td><code>Thug_URL_Info</code>, <code>Thug_HTML_Info</code></td>
    <td>performs hybrid dynamic/static analysis on a URL or HTML page.</td>
  </tr>
  <tr>
    <td>Box-JS</td>
    <td><code>BoxJS_Scan_JavaScript</code></td>
    <td>tool for studying JavaScript malware</td>
  </tr>
  <tr>
    <td>APK Analyzers</td>
    <td><code>APKiD_Scan_APK_DEX_JAR</code></td>
    <td>identifies many compilers, packers, obfuscators, and other weird stuff from an APK or DEX file</td>
  </tr>
  <tr>
    <td>TOR Analyzers</td>
    <td><code>Onionscan</code></td>
    <td>Scans TOR .onion domains for privacy leaks and information disclosures.</td>
  </tr>
  <tr>
    <td>Qiling</td>
    <td><code>Qiling_Windows</code>
    <code>Qiling_Windows_Shellcode</code>
    <code>Qiling_Linux</code>
    <code>Qiling_Linux_Shellcode</code>
    </td>
    <td>Tool for emulate the execution of a binary file or a shellcode.
     It requires the configuration of its rootfs, and the optional configuration of profiles.
     The rootfs can be copied from the <a href="https://github.com/qilingframework/qiling/tree/master/examples/rootfs"> Qiling project</a>: please remember that Windows dll <b> must</b> be manually added for license reasons.
     Qiling provides a <a href="https://github.com/qilingframework/qiling/blob/master/examples/scripts/dllscollector.bat"> DllCollector</a> to retrieve dlls from your licensed Windows. 
     <a href="https://docs.qiling.io/en/latest/profile/"> Profiles </a> must be placed in the <code>profiles</code> subfolder
     </td>
  </tr>
  <tr>
    <td>Renderton</td>
    <td><code>Renderton</code></td>
    <td>get screenshot of a web page using rendertron (a headless chrome solution using puppeteer). Configuration variables have to be included in the `config.json`, see <a href="https://github.com/GoogleChrome/rendertron#config"> config options of renderton </a>. To use a proxy, include an argument <code>--proxy-server=YOUR_PROXY_SERVER</code> in <code>puppeteerArgs</code>.</td>
  </tr>
</table>


To enable all the optional analyzers you can add the option `--all_analyzers` when starting the project. Example:
```bash
python3 start.py prod --all_analyzers up
```

Otherwise you can enable just one of the cited integration by using the related option. Example:
```bash
python3 start.py prod --qiling up
```

## Customize analyzer execution at time of request
Some analyzers and connectors provide the chance to customize the performed analysis based on parameters (`params` attr in the configuration file) that are different for each analyzer. 

- You can set a custom default values by changing their `value` attribute directly from the configuration files.
- You can choose to provide runtime configuration when requesting an analysis that will be merged with the default overriding it. This override is done only for the specific analysis.

<div class="admonition info">
<p class="admonition-title">Info</p>
Connectors parameters can only be changed from it's configuration file, not at the time of analysis request.
</div>


##### View and understand different parameters

To see the list of these parameters:
- You can view the "Analyzers Table", [here](https://intelowlclient.firebaseapp.com/pages/analyzers/table).
- You can view the raw JSON configuration file, [here](https://github.com/intelowlproject/IntelOwl/blob/master/configuration/analyzer_config.json).

##### from the GUI
You can click on "**CUSTOMIZE ANALYZERS PARAMETERS**" button and add the runtime configuration in the form of a dictionary.
Example:
```javascript
"VirusTotal_v3_Get_File": {
    "force_active_scan_if_old": true
}
```

##### from [Pyintelowl](https://github.com/intelowlproject/pyintelowl)
While using `send_observable_analysis_request` or `send_file_analysis_request` endpoints, you can pass the parameter `runtime_configuration` with the optional values.
Example:
```python
runtime_configuration = {
    "Doc_Info": {
        "additional_passwords_to_check": ["passwd", "2020"]
    }
}
pyintelowl_client.send_file_analysis_request(..., runtime_configuration=runtime_configuration)
```

## Analyzers with special configuration
Some analyzers could require a special configuration:
* `GoogleWebRisk`: this analyzer needs a service account key with the Google Cloud credentials to work properly.
You should follow the [official guide](https://cloud.google.com/web-risk/docs/quickstart) for creating the key.
Then you can copy the generated JSON key file in the directory `configuration` of the project and change its name to `service_account_keyfile.json`.
This is the default configuration. If you want to customize the name or the location of the file, you can change the environment variable `GOOGLE_APPLICATION_CREDENTIALS` in the `env_file_app` file.
* `ClamAV`: this Docker-based analyzer using `clamd` daemon as it's scanner, communicating with `clamdscan` utility to scan files. The daemon requires 2 different configuration files: `clamd.conf`(daemon's config) and `freshclam.conf` (virus database updater's config). These files are mounted as docker volumes and hence, can be edited by the user as per needs.

## Elastic Search
Intel Owl makes use of [django-elasticsearch-dsl](https://django-elasticsearch-dsl.readthedocs.io/en/latest/about.html) to index Job results into elasticsearch. The `save` and `delete` operations are auto-synced so you always have the latest data in ES.

In the `env_file_app_template`, you'd see various elasticsearch related environment variables. The user should spin their own Elastic Search instance and configure these variables.

#### Kibana
Intel Owl provides a Kibana's "Saved Object" configuration (with example dashboard and visualizations). It can be downloaded from [here](https://github.com/intelowlproject/IntelOwl/blob/develop/configuration/Kibana-Saved-Conf.ndjson) and can be imported into Kibana by going to the "Saved Objects" panel (http://localhost:5601/app/management/kibana/objects).

#### Example Configuration
1. Setup [Elastic Search and Kibana](https://hub.docker.com/r/nshou/elasticsearch-kibana/) and say it is running in a docker service with name `elasticsearch` on port `9200` which is exposed to the shared docker network.
   (Alternatively, you can spin up a local Elastic Search instance, by appending ```--elastic``` to the ```python3 start.py ...``` command. Note that the local Elastic Search instance consumes large amount of memory, and hence having >=16GB is recommended.))
2. In the `env_file_app`, we set `ELASTICSEARCH_ENABLED` to `True` and `ELASTICSEARCH_HOST` to `elasticsearch:9200`.
3. In the `Dockerfile`, set the correct version in `ELASTICSEARCH_DSL_VERSION` [depending on the version](https://django-elasticsearch-dsl.readthedocs.io/en/latest/about.html#features) of our elasticsearch server. Default value is `7.1.4`.
4. Rebuild the docker images with `docker-compose build` (required only if `ELASTICSEARCH_DSL_VERSION` was changed)
5. Now start the docker containers and execute,

  ```bash
  docker exec -ti intelowl_uwsgi python manage.py search_index --rebuild
  ```

  This will build and populate all existing job objects into the `jobs` index.



## Django Groups & Permissions
The application makes use of [Django's built-in permissions system](https://docs.djangoproject.com/en/3.0/topics/auth/default/#permissions-and-authorization). It provides a way to assign permissions to specific users and groups of users.

As an administrator here's what you need to know,
- Each user should belong to at least a single group and permissions should be assigned to these groups. Please refrain from assigning user level permissions.
- When you create a first normal user, a group with name `DefaultGlobal` is created with all permissions granted. Every new user automatically gets added to this group.
   - This is done because most admins won't need to deal with user permissions and this way, they don't have to.
   - If you don't want a global group (with all permissions) but custom groups with custom permissions,
   just strip `DefaultGlobal` of all permissions but do *not* delete it.

The permissions work the way one would expect,

<table style="width:100%">
  <tr>
    <th>Permission Name</th>
    <th>Description</th>
  </tr>
  <tr>
    <td><code>api_app | job | Can create job</code></td>
    <td>Allows users to request new analysis. When user creates a job (requests new analysis),
    - the object level <code>view</code> permission is applied to all groups the requesting user belongs to or to all groups (depending on the parameters passed).</td>
  </tr>
  <tr>
    <td><code>api_app | job | Can view job</code></td>
    <td>Allows users to fetch list of all jobs they have permission for or a particular job with it's ID.</td>
  </tr>
  <tr>
    <td><code>api_app | job | Can change job</code></td>
    <td>Allows user to change job attributes (eg: kill a running analysis). The object level permission is applied to all groups the requesting user belongs to.</td>
  </tr>
  <tr>
    <td><code>api_app | job | Can change job</code></td>
    <td>Allows user to delete an existing job. The object level permission is applied to all groups the requesting user belongs to.</td>
  </tr>
  <tr>
    <td><code>api_app | tag | Can create tag</code></td>
    <td>
      Allows users to create new tags. When user creates a new tag,
      <ul>
        <li>this new tag is visible (object level `view` permission) to each and every group but,</li>
        <li>the object level `change` and `delete` permission is given to only those groups the requesting user belongs to.</li>
        <li>This is done because tag labels and colors are unique columns and the admin in most cases would want to define tags that are usable (but not modifiable) by users of all groups.</li>
      </ul>
    </td>
  </tr>
  <tr>
    <td><code>api_app | tag | Can view tag</code></td>
    <td>Allows users to fetch list of all tags or a particular tag with it's ID</td>
  </tr>
  <tr>
    <td><code>api_app | tag | Can change tag</code></td>
    <td>allows users to edit a tag granted that user has the object level permission for the particular tag</td>
  </tr>
</table>


## Authentication options
IntelOwl provides support for some of the most common authentication methods:
* LDAP
* GSuite (work in progress)

#### LDAP
IntelOwl leverages [Django-auth-ldap](https://github.com/django-auth-ldap/django-auth-ldap) to perform authentication via LDAP.

How to configure and enable LDAP on Intel Owl?

1. Change the values with your LDAP configuration inside `configuration/ldap_config.py`. This file is mounted as a docker volume, so you won't need to rebuild the image.

>  For more details on how to configure this file, check the [official documentation](https://django-auth-ldap.readthedocs.io/en/latest/) of the django-auth-ldap library.

2. Once you have done that, you have to set the environment variable `LDAP_ENABLED` as `True` in the environment configuration file `env_file_app`.
  Finally, you can restart the application with `docker-compose up`


#### RADIUS Authentication

IntelOwl leverages [Django-radius](https://github.com/robgolding/django-radius) to perform authentication
via RADIUS server.

How to configure and enable RADIUS authentication on Intel Owl?

1. Change the values with your RADIUS auth configuration inside `configuration/radius_config.py`. This file is mounted as a
   docker volume, so you won't need to rebuild the image.

> For more details on how to configure this file, check the [official documentation](https://github.com/robgolding/django-radius) of the django-radius library.

2. Once you have done that, you have to set the environment variable `RADIUS_AUTH_ENABLED` as `True` in the environment
   configuration file `env_file_app`. Finally, you can restart the application with `docker-compose up`


## Google Kubernetes Engine deployment
Refer to the following blog post for an example on how to deploy IntelOwl on Google Kubernetes Engine:

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
In that case, you should change the parameter `BROKER_URL` to `sqs://` and give your instances on AWS the proper permissions to access it.

Also, you need to set the environment variable `AWS_SQS` to `True` to activate the additional required settings.

#### S3
If you prefer to use S3 to store the samples, instead of a local storage, you can now do it.  

First, you need to configure the environment variable `LOCAL_STORAGE` to `False` to enable it and set `AWS_STORAGE_BUCKET_NAME` to the proper AWS bucket.
Then you have to add some credentials for AWS: if you have IntelOwl deployed on the AWS infrastructure, you can use IAM credentials:
to allow that just set `AWS_IAM_ACCESS` to `True`. If that is not the case, you have to set both `AWS_ACESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
