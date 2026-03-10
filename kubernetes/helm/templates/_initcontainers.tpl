{{/*
Wait for database init container
Uses pg_isready for proper PostgreSQL readiness check (not just TCP)
*/}}
{{- define "intelowl.waitForDbInitContainer" -}}
- name: wait-for-db
  image: postgres:16-alpine
  command:
    - sh
    - -c
    - |
      until pg_isready -h {{ include "intelowl.databaseHost" . }} -p {{ include "intelowl.databasePort" . }}; do
        echo "Waiting for database to be ready..."
        sleep 3
      done
      echo "Database is ready!"
  resources:
    requests:
      memory: "32Mi"
      cpu: "10m"
    limits:
      memory: "64Mi"
      cpu: "50m"
{{- end }}

{{/*
Wait for Redis init container
*/}}
{{- define "intelowl.waitForRedisInitContainer" -}}
- name: wait-for-redis
  image: busybox:1.36
  command:
    - sh
    - -c
    - |
      until nc -z {{ include "intelowl.redisHost" . }} {{ include "intelowl.redisPort" . }}; do
        echo "Waiting for Redis..."
        sleep 2
      done
      echo "Redis is ready!"
  resources:
    requests:
      memory: "32Mi"
      cpu: "10m"
    limits:
      memory: "64Mi"
      cpu: "50m"
{{- end }}

{{/*
Initialize directories init container
Creates required log and file directories
*/}}
{{- define "intelowl.initDirectoriesContainer" -}}
- name: init-directories
  image: busybox:1.36
  command:
    - sh
    - -c
    - |
      mkdir -p /var/log/intel_owl/django
      mkdir -p /var/log/intel_owl/celery
      mkdir -p /opt/deploy/intel_owl/files
      echo "Directories initialized!"
  volumeMounts:
    - name: generic-logs
      mountPath: /var/log/intel_owl
    - name: shared-files
      mountPath: /opt/deploy/intel_owl/files
  resources:
    requests:
      memory: "32Mi"
      cpu: "10m"
    limits:
      memory: "64Mi"
      cpu: "50m"
{{- end }}

{{/*
Wait for uWSGI init container
*/}}
{{- define "intelowl.waitForUwsgiInitContainer" -}}
- name: wait-for-uwsgi
  image: busybox:1.36
  command:
    - sh
    - -c
    - |
      until nc -z {{ include "intelowl.fullname" . }}-uwsgi {{ .Values.uwsgi.service.port }}; do
        echo "Waiting for uWSGI..."
        sleep 2
      done
      echo "uWSGI is ready!"
  resources:
    requests:
      memory: "32Mi"
      cpu: "10m"
    limits:
      memory: "64Mi"
      cpu: "50m"
{{- end }}
