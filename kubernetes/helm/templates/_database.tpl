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
