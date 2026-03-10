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
- name: OLD_JOBS_RETENTION_DAYS
  value: {{ .Values.app.oldJobsRetentionDays | quote }}
{{- if .Values.app.httpsEnabled }}
- name: HTTPS_ENABLED
  value: "true"
{{- end }}
{{- if .Values.elasticsearch.enabled }}
- name: ELASTICSEARCH_DSL_ENABLED
  value: "true"
- name: ELASTICSEARCH_DSL_HOST
  value: {{ printf "%s-es-http" (include "intelowl.fullname" .) | quote }}
- name: ELASTICSEARCH_DSL_PORT
  value: "9200"
- name: ELASTICSEARCH_DSL_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "intelowl.fullname" . }}-es-es-elastic-user
      key: elastic
{{- end }}
{{- if .Values.app.slack.enabled }}
- name: SLACK_TOKEN
  valueFrom:
    secretKeyRef:
      name: {{ include "intelowl.appSecretsName" . }}
      key: slack-token
- name: DEFAULT_SLACK_CHANNEL
  value: {{ .Values.app.slack.defaultChannel | quote }}
{{- end }}
{{- if .Values.app.email.enabled }}
- name: DEFAULT_FROM_EMAIL
  value: {{ .Values.app.email.defaultFromEmail | quote }}
- name: DEFAULT_EMAIL
  value: {{ .Values.app.email.defaultEmail | quote }}
- name: EMAIL_HOST
  value: {{ .Values.app.email.host | quote }}
- name: EMAIL_PORT
  value: {{ .Values.app.email.port | quote }}
- name: EMAIL_HOST_USER
  value: {{ .Values.app.email.hostUser | quote }}
{{- if .Values.app.email.hostPassword }}
- name: EMAIL_HOST_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "intelowl.appSecretsName" . }}
      key: email-password
{{- end }}
- name: EMAIL_USE_TLS
  value: {{ .Values.app.email.useTls | quote }}
- name: EMAIL_USE_SSL
  value: {{ .Values.app.email.useSsl | quote }}
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
