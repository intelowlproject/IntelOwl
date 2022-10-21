# Advanced Usage

This page includes details about some advanced features that Intel Owl provides which can be optionally enabled. Namely,

- [Advanced Usage](#advanced-usage)
  - [Optional Analyzers](#optional-analyzers)
  - [Customize analyzer execution](#customize-analyzer-execution)
    - [View and understand different parameters](#view-and-understand-different-parameters)
    - [from the GUI](#from-the-gui)
    - [from Pyintelowl](#from-pyintelowl)
    - [CyberChef](#cyberchef)
  - [Analyzers with special configuration](#analyzers-with-special-configuration)
  - [Organizations and data sharing](#organizations-and-data-sharing)
  - [Notifications](#notifications)
  - [Elastic Search](#elastic-search)
    - [Kibana](#kibana)
    - [Example Configuration](#example-configuration)
  - [Authentication options](#authentication-options)
    - [OAuth support](#google-oauth2)
    - [LDAP](#ldap)
    - [RADIUS](#radius-authentication)
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
    <td>Malware Tools Analyzers</td>
    <td>
      <ul>
      <li><code>PEframe_Scan</code></li>
      <li><code>Capa_Info</code></li>
      <li><code>Floss</code></li>
      <li><code>Strings_Info_Classic</code>,
      <code>Strings_Info_ML</code></li>
      <li><code>Manalyze</code></li>
      <li><code>ClamAV</code></li>
      <li><code>Thug_URL_Info</code>,
      <code>Thug_HTML_Info</code></li>
      <li><code>BoxJS_Scan_JavaScript</code></li>
      <li><code>APKiD_Scan_APK_DEX_JAR</code></li>
      <li><code>Qiling_Windows</code>,
      <code>Qiling_Windows_Shellcode</code>,
      <code>Qiling_Linux</code>,
      <code>Qiling_Linux_Shellcode</code></li>
     </ul>
    </td>
    <td>
    <ul>
      <li>PEFrame performs static analysis on Portable Executable malware and malicious MS Office documents</li>
      <li>Capa detects capabilities in executable files</li>
      <li>FLOSS automatically deobfuscate strings from malware binaries</li>
      <li>String_Info_Classic extracts human-readable strings where as ML version of it ranks them</li>
      <li>Manalyze statically analyzes PE (Portable-Executable) files in-depth</li>
      <li>ClamAV antivirus engine scans files for trojans, viruses, malwares using a multi-threaded daemon</li>
      <li>Thug performs hybrid dynamic/static analysis on a URL or HTML page.</li>
      <li>Box-JS is a tool for studying JavaScript malware</li>
      <li>APKiD identifies many compilers, packers, obfuscators, and other weird stuff from an APK or DEX file</li>
      <li>Qiling is a tool for emulating the execution of a binary file or a shellcode.
     It requires the configuration of its rootfs, and the optional configuration of profiles.
     The rootfs can be copied from the <a href="https://github.com/qilingframework/qiling/tree/master/examples/rootfs"> Qiling project</a>: please remember that Windows dll <b> must</b> be manually added for license reasons.
     Qiling provides a <a href="https://github.com/qilingframework/qiling/blob/master/examples/scripts/dllscollector.bat"> DllCollector</a> to retrieve dlls from your licensed Windows. 
     <a href="https://docs.qiling.io/en/latest/profile/"> Profiles </a> must be placed in the <code>profiles</code> subfolder
     </li>
      </ul>
    </td>
  </tr>
  <tr>
    <td>TOR Analyzers</td>
    <td><code>Onionscan</code></td>
    <td>Scans TOR .onion domains for privacy leaks and information disclosures.</td>
  </tr>
  <tr>
    <td>Renderton</td>
    <td><code>Renderton</code></td>
    <td>get screenshot of a web page using rendertron (a headless chrome solution using puppeteer). Configuration variables have to be included in the `config.json`, see <a href="https://github.com/GoogleChrome/rendertron#config"> config options of renderton </a>. To use a proxy, include an argument <code>--proxy-server=YOUR_PROXY_SERVER</code> in <code>puppeteerArgs</code>.</td>
  </tr>
  <tr>
    <td>CyberChef</td>
    <td><code>CyberChef</code></td>
    <td>Run a transformation on a <a href="https://github.com/gchq/CyberChef-server">CyberChef server</a> using pre-defined or custom recipes(rules that describe how the input has to be transformed). Check further instructions <a href="#cyberchef">here</a></td>
  </tr>
    <tr>
    <td>PCAP Analyzers</td>
    <td><code>Suricata</code></td>
    <td>You can upload a PCAP to have it analyzed by Suricata with the open Ruleset. The result will provide a list of the triggered signatures plus a more detailed report with all the raw data generated by Suricata. You can also add your own rules (See paragraph "Analyzers with special configuration"). The installation is optimized for scaling so the execution time is really fast.</td>
  </tr>
</table>

To enable all the optional analyzers you can add the option `--all_analyzers` when starting the project. Example:

```bash
python3 start.py prod --all_analyzers up
```

Otherwise you can enable just one of the cited integration by using the related option. Example:

```bash
python3 start.py prod --tor_analyzers up
```

## Customize analyzer execution

Some analyzers and connectors provide the chance to customize the performed analysis based on parameters (`params` attr in the configuration file) that are different for each analyzer.

- You can set a custom default values by changing their `value` attribute directly from the configuration files. Since IntelOwl v4, it is possible to change these values directly from the GUI in the section "Your plugin configuration".
- You can choose to provide runtime configuration when requesting an analysis that will be merged with the default overriding it. This override is done only for the specific analysis.

<div class="admonition info">
<p class="admonition-title">Info</p>
Connectors parameters can only be changed from either their configuration file or the "Your plugin configuration" section, not at the time of analysis request.
</div>

##### View and understand different parameters

To see the list of these parameters:

- You can view the "Plugin" Section in IntelOwl to have a complete and updated view of all the options available
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

#### CyberChef

You can either use pre-defined recipes or create your own as
explained [here](https://github.com/gchq/CyberChef-server#features).

To use a pre-defined recipe, set the `predefined_recipe_name` argument to the name of the recipe as
defined [here](#pre-defined-recipes). Else, leave the `predefined_recipe_name` argument empty and set
the `custom_recipe` argument to the contents of
the [recipe](https://github.com/gchq/CyberChef-server#example-one-operation-non-default-arguments-by-name) you want to
use.

Additionally, you can also (optionally) set the `output_type` argument.

##### Pre-defined recipes

- "to decimal": `[{"op": "To Decimal", "args": ["Space", False]}]`

## Analyzers with special configuration

Some analyzers could require a special configuration:

- `GoogleWebRisk`: this analyzer needs a service account key with the Google Cloud credentials to work properly.
  You should follow the [official guide](https://cloud.google.com/web-risk/docs/quickstart) for creating the key.
  Then you can copy the generated JSON key file in the directory `configuration` of the project and change its name to `service_account_keyfile.json`.
  This is the default configuration. If you want to customize the name or the location of the file, you can change the environment variable `GOOGLE_APPLICATION_CREDENTIALS` in the `env_file_app` file.

- `ClamAV`: this Docker-based analyzer using `clamd` daemon as it's scanner, communicating with `clamdscan` utility to scan files. The daemon requires 2 different configuration files: `clamd.conf`(daemon's config) and `freshclam.conf` (virus database updater's config). These files are mounted as docker volumes in `/integrations/malware_tools_analyzers/clamav` and hence, can be edited by the user as per needs, without restarting the application.

- `Suricata`: you can customize the behavior of Suricata:
  - `/integrations/pcap_analyzers/config/suricata/rules`: here there are Suricata rules. You can change the `custom.rules` files to add your own rules at any time. Once you made this change, you need to either restart IntelOwl or (this is faster) run a new analysis with the Suricata analyzer and set the parameter `reload_rules` to `true`.
  - `/integrations/pcap_analyzers/config/suricata/etc`: here there are Suricata configuration files. Change it based on your wish. Restart IntelOwl to see the changes applied.

- `Yara_Scan_Custom_Signatures`: you can use this pre-defined analyzer to run your own YARA signatures, either custom or imported. Just upload the `.yar` files with the signatures in the directory `/configuration/custom_yara`. That directory is mounted as a bind volume in Docker so you do not need to do anything to see the changes in the application.

## Organizations and data sharing

Organizations are a great way to share data and analysis only with the members of your team. Invite the people you work with in your organization!

By default, analysis (jobs) are executed with a level of TLP that is WHITE. This means that these jobs are public and every IntelOwl user can see them.
Thanks to the "Organization" feature, you can restrict the people who can see the analysis that you made.

How you can do that?
Jobs with either AMBER or RED TLP value will be accessible to only members within the same organization. You can select the TLP for the analysis at the time of request.

## Notifications

Since v4, IntelOwl integrated the notification system from the `certego_saas` package, allowing the admins to create notification that every user will be able to see.

The user would find the Notifications button on the top right of the page:

<img style="border: 0.2px solid black" width=220 height=210 src="https://raw.githubusercontent.com/intelowlproject/IntelOwl/master/docs/static/notifications.png">

There the user can read notifications provided by either the administrators or the IntelOwl Maintainers.

As an Admin, if you want to add a notification to have it sent to all the users, you have to login to the Django Admin interface, go to the "Notifications" section and add it there.
While adding a new notification, in the `body` section it is possible to even use HTML syntax, allowing to embed images, links, etc;
in the `app_name field`, please remember to use `intelowl` as the app name.

Everytime a new release is installed, once the backend goes up it will automatically create a new notification,
having as content the latest changes described in the [CHANGELOG.md](https://github.com/intelowlproject/IntelOwl/blob/master/.github/CHANGELOG.md),
allowing the users to keep track of the changes inside intelowl itself.

## Elastic Search

Intel Owl makes use of [django-elasticsearch-dsl](https://django-elasticsearch-dsl.readthedocs.io/en/latest/about.html) to index Job results into elasticsearch. The `save` and `delete` operations are auto-synced so you always have the latest data in ES.

In the `env_file_app_template`, you'd see various elasticsearch related environment variables. The user should spin their own Elastic Search instance and configure these variables.

#### Kibana

Intel Owl provides a Kibana's "Saved Object" configuration (with example dashboard and visualizations). It can be downloaded from [here](https://github.com/intelowlproject/IntelOwl/blob/develop/configuration/Kibana-Saved-Conf.ndjson) and can be imported into Kibana by going to the "Saved Objects" panel (http://localhost:5601/app/management/kibana/objects).

#### Example Configuration

1. Setup [Elastic Search and Kibana](https://hub.docker.com/r/nshou/elasticsearch-kibana/) and say it is running in a docker service with name `elasticsearch` on port `9200` which is exposed to the shared docker network.
   (Alternatively, you can spin up a local Elastic Search instance, by appending `--elastic` to the `python3 start.py ...` command. Note that the local Elastic Search instance consumes large amount of memory, and hence having >=16GB is recommended.))
2. In the `env_file_app`, we set `ELASTICSEARCH_ENABLED` to `True` and `ELASTICSEARCH_HOST` to `elasticsearch:9200`.
3. In the `Dockerfile`, set the correct version in `ELASTICSEARCH_DSL_VERSION` [depending on the version](https://django-elasticsearch-dsl.readthedocs.io/en/latest/about.html#features) of our elasticsearch server. Default value is `7.1.4`.
4. Rebuild the docker images with `docker-compose build` (required only if `ELASTICSEARCH_DSL_VERSION` was changed)
5. Now start the docker containers and execute,

```bash
docker exec -ti intelowl_uwsgi python manage.py search_index --rebuild
```

This will build and populate all existing job objects into the `jobs` index.

## Authentication options

IntelOwl provides support for some of the most common authentication methods:

- Google Oauth2
- LDAP
- RADIUS

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

