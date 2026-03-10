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
