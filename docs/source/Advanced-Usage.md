# Advanced Usage

This page includes details about some advanced features that Intel Owl provides which can be optionally enabled. Namely,

- [Elastic Search (with Kibana)](#elastic-search)
- [Django Groups & Permissions](#django-groups-&-permissions)
- [Optional Analyzers](#optional-analyzers)

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
  </tr>
  <tr>
    <td>PEframe</td>
    <td><code>PEframe_Scan</code></td>
  </tr>
  <tr>
    <td>Thug</td>
    <td><code>Thug_URL_Info_*</code>, <code>Thug_HTML_Info_*</code></td>
  </tr>
  <tr>
    <td>FireEye Capa</td>
    <td><code>Capa_Info</code></td>
  </tr>
  <tr>
    <td>Box-JS</td>
    <td><code>BoxJS_Scan_JavaScript</code></td>
  </tr>
  <tr>
    <td>APK Analyzers</td>
    <td><code>APKiD_Scan_APK_DEX_JAR</code></td>
  </tr>
</table>

In the project, you can find template files named `.env_template` and `.env_file_integrations_template`.
You have to create new files named `.env` and `env_file_integrations` from these two templates.

Docker services defined in the compose files added in `COMPOSE_FILE` variable present in the `.env` file are ran on `docker-compose up`. So, modify it to include only the analyzers you wish to use.
Such compose files are available under `integrations/`.