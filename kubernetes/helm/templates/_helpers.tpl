{{/*
Expand the name of the chart.
*/}}
{{- define "intelowl.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "intelowl.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "intelowl.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "intelowl.labels" -}}
helm.sh/chart: {{ include "intelowl.chart" . }}
{{ include "intelowl.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "intelowl.selectorLabels" -}}
app.kubernetes.io/name: {{ include "intelowl.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Component labels
*/}}
{{- define "intelowl.componentLabels" -}}
{{ include "intelowl.labels" . }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "intelowl.serviceAccountName" -}}
{{- if .Values.rbac.create }}
{{- default (include "intelowl.fullname" .) .Values.rbac.serviceAccountName }}
{{- else }}
{{- default "default" .Values.rbac.serviceAccountName }}
{{- end }}
{{- end }}

{{/*
Return the proper image name
*/}}
{{- define "intelowl.image" -}}
{{- $registryName := .Values.global.imageRegistry | default "" -}}
{{- $repositoryName := .imageRoot.repository -}}
{{- $tag := .imageRoot.tag | default .Chart.AppVersion | toString -}}
{{- if $registryName }}
{{- printf "%s/%s:%s" $registryName $repositoryName $tag -}}
{{- else }}
{{- printf "%s:%s" $repositoryName $tag -}}
{{- end }}
{{- end }}

{{/*
Return the proper nginx image name
*/}}
{{- define "intelowl.nginxImage" -}}
{{- $registryName := .Values.global.imageRegistry | default "" -}}
{{- $repositoryName := .Values.nginx.image.repository -}}
{{- $tag := .Values.nginx.image.tag | default .Chart.AppVersion | toString -}}
{{- if $registryName }}
{{- printf "%s/%s:%s" $registryName $repositoryName $tag -}}
{{- else }}
{{- printf "%s:%s" $repositoryName $tag -}}
{{- end }}
{{- end }}

{{/*
Return the database host
For CloudNative-PG, the read-write service is named <cluster>-rw
*/}}
{{- define "intelowl.databaseHost" -}}
{{- if .Values.database.internal }}
{{- printf "%s-postgres-rw" (include "intelowl.fullname" .) }}
{{- else }}
{{- .Values.database.external.host }}
{{- end }}
{{- end }}

{{/*
Return the database read-only host (for read replicas)
For CloudNative-PG, the read-only service is named <cluster>-ro
*/}}
{{- define "intelowl.databaseHostReadOnly" -}}
{{- if .Values.database.internal }}
{{- printf "%s-postgres-ro" (include "intelowl.fullname" .) }}
{{- else }}
{{- .Values.database.external.host }}
{{- end }}
{{- end }}

{{/*
Return the database port
*/}}
{{- define "intelowl.databasePort" -}}
{{- if .Values.database.internal }}
{{- print "5432" }}
{{- else }}
{{- .Values.database.external.port | default 5432 }}
{{- end }}
{{- end }}

{{/*
Return the database name
*/}}
{{- define "intelowl.databaseName" -}}
{{- if .Values.database.internal }}
{{- .Values.postgresql.database | default "intel_owl_db" }}
{{- else }}
{{- .Values.database.external.name }}
{{- end }}
{{- end }}

{{/*
Return the database user
*/}}
{{- define "intelowl.databaseUser" -}}
{{- if .Values.database.internal }}
{{- .Values.postgresql.username | default "intelowl" }}
{{- else }}
{{- .Values.database.external.user }}
{{- end }}
{{- end }}

{{/*
Return the database secret name
For CloudNative-PG, credentials are stored in <cluster>-credentials secret
*/}}
{{- define "intelowl.databaseSecretName" -}}
{{- if .Values.database.internal }}
{{- if .Values.postgresql.existingSecret }}
{{- .Values.postgresql.existingSecret }}
{{- else }}
{{- printf "%s-postgres-credentials" (include "intelowl.fullname" .) }}
{{- end }}
{{- else }}
{{- if .Values.database.external.existingSecret }}
{{- .Values.database.external.existingSecret }}
{{- else }}
{{- printf "%s-app-secrets" (include "intelowl.fullname" .) }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Return the database password key in secret
For CloudNative-PG, the key is "password" in basic-auth secret
*/}}
{{- define "intelowl.databasePasswordKey" -}}
{{- if .Values.database.internal }}
{{- print "password" }}
{{- else }}
{{- print "db-password" }}
{{- end }}
{{- end }}

{{/*
Return the Gateway name
*/}}
{{- define "intelowl.gatewayName" -}}
{{- if .Values.networking.gateway.name }}
{{- .Values.networking.gateway.name }}
{{- else }}
{{- printf "%s-gateway" (include "intelowl.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Return the Gateway controller name based on provider
*/}}
{{- define "intelowl.gatewayControllerName" -}}
{{- $provider := .Values.networking.gatewayProvider | default "nginx-gateway-fabric" }}
{{- if eq $provider "nginx-gateway-fabric" }}
{{- print "gateway.nginx.org/nginx-gateway-controller" }}
{{- else if eq $provider "envoy-gateway" }}
{{- print "gateway.envoyproxy.io/gatewayclass-controller" }}
{{- else if eq $provider "istio" }}
{{- print "istio.io/gateway-controller" }}
{{- else if eq $provider "kong" }}
{{- print "konghq.com/kic-gateway-controller" }}
{{- else if eq $provider "traefik" }}
{{- print "traefik.io/gateway-controller" }}
{{- else }}
{{- print "gateway.nginx.org/nginx-gateway-controller" }}
{{- end }}
{{- end }}

{{/*
Return the Redis host
For CloudPirates Redis, the service is named <release>-redis
*/}}
{{- define "intelowl.redisHost" -}}
{{- if .Values.broker.redis.internal }}
{{- printf "%s-redis" (include "intelowl.fullname" .) }}
{{- else }}
{{- .Values.broker.redis.external.host }}
{{- end }}
{{- end }}

{{/*
Return the Redis port
*/}}
{{- define "intelowl.redisPort" -}}
{{- if .Values.broker.redis.internal }}
{{- print "6379" }}
{{- else }}
{{- .Values.broker.redis.external.port | default 6379 }}
{{- end }}
{{- end }}

{{/*
Return the Redis secret name
*/}}
{{- define "intelowl.redisSecretName" -}}
{{- if .Values.broker.redis.internal }}
{{- if .Values.redis.auth.existingSecret }}
{{- .Values.redis.auth.existingSecret }}
{{- else }}
{{- printf "%s-redis" (include "intelowl.fullname" .) }}
{{- end }}
{{- else }}
{{- if .Values.broker.redis.external.existingSecret }}
{{- .Values.broker.redis.external.existingSecret }}
{{- else }}
{{- printf "%s-app-secrets" (include "intelowl.fullname" .) }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Return the Redis password key in secret
*/}}
{{- define "intelowl.redisPasswordKey" -}}
{{- if .Values.broker.redis.internal }}
{{- print "redis-password" }}
{{- else }}
{{- print "redis-password" }}
{{- end }}
{{- end }}

{{/*
Return the RabbitMQ host
For CloudPirates RabbitMQ, the service is named <release>-rabbitmq
*/}}
{{- define "intelowl.rabbitmqHost" -}}
{{- if .Values.broker.rabbitmq.internal }}
{{- printf "%s-rabbitmq" (include "intelowl.fullname" .) }}
{{- else }}
{{- .Values.broker.rabbitmq.external.host }}
{{- end }}
{{- end }}

{{/*
Return the RabbitMQ port
*/}}
{{- define "intelowl.rabbitmqPort" -}}
{{- if .Values.broker.rabbitmq.internal }}
{{- print "5672" }}
{{- else }}
{{- .Values.broker.rabbitmq.external.port | default 5672 }}
{{- end }}
{{- end }}

{{/*
Return the RabbitMQ user
*/}}
{{- define "intelowl.rabbitmqUser" -}}
{{- if .Values.broker.rabbitmq.internal }}
{{- .Values.rabbitmq.auth.username | default "intelowl" }}
{{- else }}
{{- .Values.broker.rabbitmq.external.user | default "guest" }}
{{- end }}
{{- end }}

{{/*
Return the RabbitMQ vhost
*/}}
{{- define "intelowl.rabbitmqVhost" -}}
{{- if .Values.broker.rabbitmq.internal }}
{{- .Values.rabbitmq.vhost | default "/" }}
{{- else }}
{{- .Values.broker.rabbitmq.external.vhost | default "/" }}
{{- end }}
{{- end }}

{{/*
Return the RabbitMQ secret name
*/}}
{{- define "intelowl.rabbitmqSecretName" -}}
{{- if .Values.broker.rabbitmq.internal }}
{{- if .Values.rabbitmq.auth.existingSecret }}
{{- .Values.rabbitmq.auth.existingSecret }}
{{- else }}
{{- printf "%s-rabbitmq" (include "intelowl.fullname" .) }}
{{- end }}
{{- else }}
{{- if .Values.broker.rabbitmq.external.existingSecret }}
{{- .Values.broker.rabbitmq.external.existingSecret }}
{{- else }}
{{- printf "%s-app-secrets" (include "intelowl.fullname" .) }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Return the RabbitMQ password key in secret
*/}}
{{- define "intelowl.rabbitmqPasswordKey" -}}
{{- if .Values.broker.rabbitmq.internal }}
{{- .Values.rabbitmq.auth.existingSecretPasswordKey | default "password" }}
{{- else }}
{{- print "rabbitmq-password" }}
{{- end }}
{{- end }}

{{/*
Return the broker URL
*/}}
{{- define "intelowl.brokerUrl" -}}
{{- if eq .Values.broker.type "redis" }}
{{- $host := include "intelowl.redisHost" . }}
{{- $port := include "intelowl.redisPort" . }}
{{- $db := .Values.broker.redis.external.db | default 0 }}
{{- printf "redis://:%s@%s:%s/%d" "$(REDIS_PASSWORD)" $host $port (int $db) }}
{{- else if eq .Values.broker.type "rabbitmq" }}
{{- $host := include "intelowl.rabbitmqHost" . }}
{{- $port := include "intelowl.rabbitmqPort" . }}
{{- $user := include "intelowl.rabbitmqUser" . }}
{{- $vhost := include "intelowl.rabbitmqVhost" . }}
{{- printf "amqp://%s:%s@%s:%s/%s" $user "$(RABBITMQ_PASSWORD)" $host $port $vhost }}
{{- else if eq .Values.broker.type "sqs" }}
{{- printf "sqs://" }}
{{- end }}
{{- end }}

{{/*
Return the result backend URL (always Redis)
*/}}
{{- define "intelowl.resultBackendUrl" -}}
{{- $host := include "intelowl.redisHost" . }}
{{- $port := include "intelowl.redisPort" . }}
{{- printf "redis://:%s@%s:%s/1" "$(REDIS_PASSWORD)" $host $port }}
{{- end }}

{{/*
Return the app secrets name
*/}}
{{- define "intelowl.appSecretsName" -}}
{{- if .Values.externalSecrets.enabled }}
{{- printf "%s-app-secrets" (include "intelowl.fullname" .) }}
{{- else if .Values.app.django.existingSecret }}
{{- .Values.app.django.existingSecret }}
{{- else }}
{{- printf "%s-app-secrets" (include "intelowl.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Common environment variables for all IntelOwl services
*/}}
{{- define "intelowl.commonEnvVars" -}}
- name: DJANGO_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ include "intelowl.appSecretsName" . }}
      key: django-secret
- name: DB_HOST
  value: {{ include "intelowl.databaseHost" . | quote }}
- name: DB_PORT
  value: {{ include "intelowl.databasePort" . | quote }}
- name: DB_NAME
  value: {{ include "intelowl.databaseName" . | quote }}
- name: DB_USER
  value: {{ include "intelowl.databaseUser" . | quote }}
- name: DB_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "intelowl.databaseSecretName" . }}
      key: {{ include "intelowl.databasePasswordKey" . }}
- name: REDIS_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "intelowl.redisSecretName" . }}
      key: {{ include "intelowl.redisPasswordKey" . }}
{{- if eq .Values.broker.type "rabbitmq" }}
- name: RABBITMQ_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "intelowl.rabbitmqSecretName" . }}
      key: {{ include "intelowl.rabbitmqPasswordKey" . }}
{{- end }}
- name: BROKER_URL
  value: {{ include "intelowl.brokerUrl" . | quote }}
- name: RESULT_BACKEND
  value: {{ include "intelowl.resultBackendUrl" . | quote }}
- name: WEBSOCKETS_URL
  value: {{ printf "redis://:%s@%s:%s/0" "$(REDIS_PASSWORD)" (include "intelowl.redisHost" .) (include "intelowl.redisPort" .) | quote }}
- name: DEBUG
  value: {{ .Values.app.django.debug | quote }}
- name: DJANGO_ALLOWED_HOSTS
  value: {{ .Values.app.django.allowedHosts | quote }}
- name: LOG_LEVEL
  value: {{ .Values.app.logLevel | quote }}
- name: DEFAULT_TIMEOUT
  value: {{ .Values.app.defaultTimeout | quote }}
{{- if .Values.app.baseUrl }}
- name: BASE_URL
  value: {{ .Values.app.baseUrl | quote }}
{{- end }}
{{- if .Values.storage.s3.enabled }}
- name: AWS_STORAGE_BUCKET_NAME
  value: {{ .Values.storage.s3.bucket | quote }}
- name: AWS_S3_REGION_NAME
  value: {{ .Values.storage.s3.region | quote }}
{{- if .Values.storage.s3.endpoint }}
- name: AWS_S3_ENDPOINT_URL
  value: {{ .Values.storage.s3.endpoint | quote }}
{{- end }}
{{- if not .Values.storage.s3.existingSecret }}
- name: AWS_ACCESS_KEY_ID
  valueFrom:
    secretKeyRef:
      name: {{ include "intelowl.appSecretsName" . }}
      key: aws-access-key-id
- name: AWS_SECRET_ACCESS_KEY
  valueFrom:
    secretKeyRef:
      name: {{ include "intelowl.appSecretsName" . }}
      key: aws-secret-access-key
{{- end }}
{{- end }}
{{- end }}

{{/*
Migration-specific environment variables (database only, no broker)
Used by the migration job which runs before Redis/RabbitMQ are available
*/}}
{{- define "intelowl.migrationEnvVars" -}}
- name: DJANGO_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ include "intelowl.appSecretsName" . }}
      key: django-secret
- name: DB_HOST
  value: {{ include "intelowl.databaseHost" . | quote }}
- name: DB_PORT
  value: {{ include "intelowl.databasePort" . | quote }}
- name: DB_NAME
  value: {{ include "intelowl.databaseName" . | quote }}
- name: DB_USER
  value: {{ include "intelowl.databaseUser" . | quote }}
- name: DB_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "intelowl.databaseSecretName" . }}
      key: {{ include "intelowl.databasePasswordKey" . }}
- name: DEBUG
  value: {{ .Values.app.django.debug | quote }}
- name: DJANGO_ALLOWED_HOSTS
  value: {{ .Values.app.django.allowedHosts | quote }}
- name: LOG_LEVEL
  value: {{ .Values.app.logLevel | quote }}
{{- end }}

{{/*
Common volume mounts for IntelOwl application services
*/}}
{{- define "intelowl.commonVolumeMounts" -}}
{{- if .Values.storage.localStorage }}
- name: generic-logs
  mountPath: /var/log/intel_owl
- name: shared-files
  mountPath: /opt/deploy/intel_owl/files
{{- end }}
{{- end }}

{{/*
Common volumes for IntelOwl application services
*/}}
{{- define "intelowl.commonVolumes" -}}
{{- if .Values.storage.localStorage }}
- name: generic-logs
  persistentVolumeClaim:
    claimName: {{ include "intelowl.fullname" . }}-generic-logs
- name: shared-files
  persistentVolumeClaim:
    claimName: {{ include "intelowl.fullname" . }}-shared-files
{{- end }}
{{- end }}

{{/*
Static volume mounts for Nginx
*/}}
{{- define "intelowl.staticVolumeMounts" -}}
{{- if .Values.storage.localStorage }}
- name: static-content
  mountPath: /var/www/static
{{- end }}
{{- end }}

{{/*
Static volumes for Nginx
*/}}
{{- define "intelowl.staticVolumes" -}}
{{- if .Values.storage.localStorage }}
- name: static-content
  persistentVolumeClaim:
    claimName: {{ include "intelowl.fullname" . }}-static-content
{{- end }}
{{- end }}

{{/*
Wait for database init container
*/}}
{{- define "intelowl.waitForDbInitContainer" -}}
- name: wait-for-db
  image: busybox:1.36
  command:
    - sh
    - -c
    - |
      until nc -z {{ include "intelowl.databaseHost" . }} {{ include "intelowl.databasePort" . }}; do
        echo "Waiting for database..."
        sleep 2
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

{{/*
Image pull secrets
*/}}
{{- define "intelowl.imagePullSecrets" -}}
{{- if .Values.global.imagePullSecrets }}
imagePullSecrets:
{{- range .Values.global.imagePullSecrets }}
  - name: {{ . }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Pod security context
*/}}
{{- define "intelowl.podSecurityContext" -}}
{{- if .Values.podSecurityContext }}
securityContext:
  {{- toYaml .Values.podSecurityContext | nindent 2 }}
{{- end }}
{{- end }}

{{/*
Container security context
*/}}
{{- define "intelowl.containerSecurityContext" -}}
{{- if .Values.containerSecurityContext }}
securityContext:
  {{- toYaml .Values.containerSecurityContext | nindent 2 }}
{{- end }}
{{- end }}

{{/*
Storage class for PVCs
*/}}
{{- define "intelowl.storageClass" -}}
{{- $storageClass := .storageClass | default .Values.global.storageClass -}}
{{- if $storageClass }}
storageClassName: {{ $storageClass | quote }}
{{- end }}
{{- end }}
