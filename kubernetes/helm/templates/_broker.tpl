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
