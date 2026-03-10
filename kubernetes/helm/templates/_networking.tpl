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
