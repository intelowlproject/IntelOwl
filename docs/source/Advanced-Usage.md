# Advanced Usage

This page includes details about some advanced features that Intel Owl provides which can be optionally enabled. Namely,

- [Smart start](#smart-start)
- [Optional Analyzers](#optional-analyzers)
- [Customize analyzer execution at time of request](#customize-analyzer-execution-at-time-of-request)
- [Elastic Search (with Kibana)](#elastic-search)
- [Django Groups & Permissions](#django-groups-permissions)
- [Authentication options](#authentication-options)
- [GKE deployment](#google-kubernetes-engine-deployment)
- [Multi Queue](#multi-queue)

## Smart start
Users that have at least Python 3.6 installed in their machine can leverage a script to help them configure and execute IntelOwl with additional or advanced configuration.

We are talking about a CLI interface called [start.py](https://github.com/intelowlproject/IntelOwl/blob/master/start.py).
```
python3 start.py --help
```

The CLI provides the primitives to correctly build, run or stop the containers for IntelOwl.
It is possible to attach every optional docker container that IntelOwl has:
this means that it is possible to have IntelOwl that runs the `multi_queue` [feature](#multi-queue) with `traefik` enabled and every [optional docker analyzer](#optional-analyzers) is active.
At last, it is possible to insert an optional docker argument, that the CLI will pass to docker.    

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
    <td><code>PEframe_Scan</code>, <code>Capa_Info</code>, <code>Floss</code>, <code>Strings_Info_Classic</code>, <code>Strings_Info_ML</code>, <code>Manalyze</code></td>
    <td>
    <ul>
      <li>Capa detects capabilities in executable files</li>
      <li>PEFrame performs static analysis on Portable Executable malware and malicious MS Office documents</li>
      <li>FLOSS automatically deobfuscate strings from malware binaries</li>
      <li>String_Info_Classic extracts human-readable strings where as ML version of it ranks them</li>
      <li>Manalyze statically analyzes PE (Portable-Executable) files in-depth</li>
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
</table>

In the project, you can find template file `.env_file_integrations_template`. You have to create new file named `env_file_integrations` from this.

Docker services defined in the compose files added in `COMPOSE_FILE` variable present in the `.env` file are ran on `docker-compose up`. So, modify it to include only the analyzers you wish to use.
Such compose files are available under `integrations/`.


## Customize analyzer execution at time of request
Some analyzers provide the chance to customize the performed analysis based on options that are different for each analyzer. This is configurable via the `CUSTOM ANALYZERS CONFIGURATION` button on the scan form or you can pass these values as a dictionary when using the pyintelowl client.

List of some of the analyzers with optional configuration:
* `VirusTotal_v3_Get_File*`:
    * `force_active_scan` (default False): if the sample is not already in VT, send the sample and perform a scan
    * `force_active_scan_if_old` (default False): if the sample is old, it would be rescanned
* `Doc_Info*`:
    * `additional_passwords_to_check`: list of passwords to try when decrypting the document
* `Thug_URL_Info` and `Thug_HTML_Info` ((defaults can be seen here [analyzer_config.json](https://github.com/intelowlproject/IntelOwl/blob/master/configuration/analyzer_config.json)):
    * `dom_events`: see [Thug doc: dom events handling](https://buffer.github.io/thug/doc/usage.html#dom-events-handling)
    * `use_proxy` and `proxy`: see [Thug doc: option -p](https://buffer.github.io/thug/doc/usage.html#basic-usage)
    * `enable_image_processing_analysis`: see [Thug doc: option -a](https://buffer.github.io/thug/doc/usage.html#basic-usage)
    * `enable_awis`: see [Thug doc: option -E](https://buffer.github.io/thug/doc/usage.html#basic-usage)
    * `user_agent`: see [Thug doc: browser personality](https://buffer.github.io/thug/doc/usage.html#browser-personality)
* `DNSDB` (defaults can be seen here [dnsdb.py](https://github.com/intelowlproject/IntelOwl/blob/master/api_app/script_analyzers/observable_analyzers/dnsdb.py)), Official [API docs](https://docs.dnsdb.info/dnsdb-apiv2/):
    * `server`: DNSDB server
    * `api_version`: API version of DNSDB
    * `rrtype`: DNS query type
    * `limit`: maximum number of results to retrieve
    * `time_first_before`, `time_first_after`, `time_last_before`, `time_last_after`
* `*_DNS` (all DNS resolvers analyzers):
    * `query_type`: query type against the chosen DNS resolver, default is "A"
* `DNStwist`:
    * `ssdeep` (default False): enable fuzzy hashing - compare HTML content of original domain with a potentially malicious one and determine similarity.
    * `mxcheck` (default False): find suspicious mail servers and flag them with SPYING-MX string.
    * `tld` (default False): check for domains with different TLDs by supplying a dictionary file.
    * `tld_dict` (default abused_tlds.dict): dictionary to use with tld argument. (common_tlds.dict/abused_tlds.dict)
* `ZoomEye`:
  * `search_type` (defualt host) Choose among `host`, `web`, `both` (both is only available to ZoomEye VIP users)
  * `query`: Follow according to [docs](https://www.zoomeye.org/doc#host-search), but omit `ip`, `hostname`. Eg: `"query": "city:biejing port:21"`
  * `facets`(default: Empty string): A comma-separated list of properties to get summary information on query. Eg: `"facets:app,os"`
  * `page`(default 1): The page number to paging
  * `history`(default True):  	To query the history data.
* `Triage_Scan` and `Triage_Search`:
  * `endpoint` (default public): choose whether to query on the public or the private endpoint of triage.
  * `report_type` (default overview): determines how detailed the final report will be. (overview/complete)
* `Triage_Search`:
  * `analysis_type` (default search): choose whether to search for existing observable reports or upload for scanning via URL. (search/submit)

There are two ways to do this:

#### from the GUI
You can click on "**Custom analyzer configuration**" button and add the runtime configuration in the form of a dictionary.
Example:
```
"VirusTotal_v3_Get_File": {
    "force_active_scan_if_old": true
}
```

#### from [Pyintelowl](https://github.com/intelowlproject/pyintelowl)
While using `send_observable_analysis_request` or `send_file_analysis_request` endpoints, you can pass the parameter `runtime_configuration` with the optional values.
Example:
```
runtime_configuration = {
    "Doc_Info": {
        "additional_passwords_to_check": ["passwd", "2020"]
    }
}
pyintelowl_client.send_file_analysis_request(..., runtime_configuration=runtime_configuration)
```


## Elastic Search

Intel Owl makes use of [django-elasticsearch-dsl](https://django-elasticsearch-dsl.readthedocs.io/en/latest/about.html) to index Job results into elasticsearch. The `save` and `delete` operations are auto-synced so you always have the latest data in ES.

In the `env_file_app_template`, you'd see various elasticsearch related environment variables. The user should spin their own Elastic Search instance and configure these variables.

#### Kibana

Intel Owl provides a saved configuration (with example dashboard and visualizations) for Kibana. It can be downloaded from [here](https://github.com/intelowlproject/IntelOwl/blob/develop/configuration/Kibana-Saved-Conf.ndjson) and can be imported into Kibana.

#### Example Configuration

1. Setup [Elastic Search and Kibana](https://hub.docker.com/r/nshou/elasticsearch-kibana/) and say it is running in a docker service with name `elk` on port `9200` which is exposed to the shared docker network.
2. In the `env_file_app`, we set `ELASTICSEARCH_ENABLED` to `True` and `ELASTICSEARCH_HOST` to `elk:9200`.
3. In the `Dockerfile`, set the correct version in `ELASTICSEARCH_DSL_VERSION` [depending on the version](https://django-elasticsearch-dsl.readthedocs.io/en/latest/about.html#features) of our elasticsearch server. Default value is `7.1.4`.
4. Rebuild the docker images with `docker-compose build` (required only if `ELASTICSEARCH_DSL_VERSION` was changed)
5. Now start the docker containers and execute,

  ```bash
  docker exec -ti intel_owl_uwsgi python manage.py search_index --rebuild
  ```

  This will build and populate all existing job objects into the `jobs` index.


## Django Groups & Permissions
The application makes use of [Django's built-in permissions system](https://docs.djangoproject.com/en/3.0/topics/auth/default/#permissions-and-authorization). It provides a way to assign permissions to specific users and groups of users.

As an administrator here's what you need to know,
- Each user should belong to atleast a single group and permissions should be assigned to these groups. Please refrain from assigning user level permissions.
- When you create a first normal user, a group with name `DefaultGlobal` is created with all permissions granted. Every new user automatically gets added to this group.
   - This is done because most admins won't need to deal with user permissions and this way, they don't have to.
   - If you don't want a global group (with all permissions) but custom groups with custom permissions,
   just strip `DefaultGlobal` of all permissions but do *not* delete it.

The permissions work the way one would expect,
- `api_app | job | Can view job` allows users to fetch list of all jobs he/she has permission for or a particular job with it's ID.
- `api_app | job | Can create job` allows users to request new analysis. When user creates a job (requests new analysis),
    - the object level `view` permission is applied to all groups the requesting user belongs to or to all groups (depending on the parameters passed). 
    - the object level `change` and `delete` permission is restricted to superusers/admin.
- `api_app | tag | Can create tag` allows users to create new tags. When user creates a new tag,
    - this new tag is visible (object level `view` permission) to each and every group but,
    - the object level `change` and `delete` permission is given to only those groups the requesting user belongs to. 
    - This is done because tag labels and colors are unique columns and the admin in most cases would want to define tags that are usable (but not modifiable) by users of all groups.
- `api_app | tag | Can view tag` allows users to fetch list of all tags or a particular tag with it's ID.
- `api_app | tag | Can change tag` allows users to edit a tag granted that user has the object level permission for the particular tag.

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


## Google Kubernetes Engine deployment
Refer to the following blog post for an example on how to deploy IntelOwl on Google Kubernetes Engine:

[Deploying Intel-Owl on GKE](https://mostwanted002.cf/post/intel-owl-gke/) by [Mayank Malik](https://twitter.com/_mostwanted002_).

## Multi Queue
IntelOwl provides an additional `docker-compose` file,  [multi-queue.override.yaml](https://github.com/intelowlproject/IntelOwl/blob/master/docker/multi-queue.override.yml) file, allowing IntelOwl users to better scale with the performance of their own architecture.
The command to correctly use the file is the following
`docker-compose -f docker/default.yaml -f docker/multi-queue.override.yaml`, leveraging the [override](https://docs.docker.com/compose/extends/) feature of docker.


It is possible to define new celery workers, each requires the addition of a new container in the docker-compose file, as shown in the `multi-queue.override.yaml`. 

IntelOwl moreover requires that the name of the workers are provided in the `docker-compose` file. This is done through the environment variable `CELERY_QUEUES` inside the `uwsgi` container. Each queue must be separated using the character `,`, as shown in the [example](https://github.com/intelowlproject/IntelOwl/blob/master/docker-compose-multi-queue.yml#L29).

Now it is possible to specify for each configuration inside [analyzer_config](https://github.com/intelowlproject/IntelOwl/blob/master/configuration/analyzer_config.json) the desired queue. If no queue are provided, the `default` queue will be selected.
 