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
Storage class for PVCs
*/}}
{{- define "intelowl.storageClass" -}}
{{- $storageClass := .storageClass | default .Values.global.storageClass -}}
{{- if $storageClass }}
storageClassName: {{ $storageClass | quote }}
{{- end }}
{{- end }}
