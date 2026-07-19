{{- define "trackone.namespace" -}}
{{ if .Values.namespace.name -}}
{{ .Values.namespace.name }}
{{ else -}}
{{ .Release.Namespace }}
{{ end -}}
{{ end -}}

{{- define "trackone.gatewayConfigMapName" -}}
{{- if .Values.gateway.existingConfigMap -}}
{{ .Values.gateway.existingConfigMap }}
{{- else -}}
trackone-gateway-config
{{- end -}}
{{- end -}}

{{- define "trackone.gatewaySecretName" -}}
{{- if .Values.gateway.existingSecret -}}
{{ .Values.gateway.existingSecret }}
{{- else -}}
trackone-gateway-env
{{- end -}}
{{- end -}}

{{- define "trackone.postgresSecretName" -}}
{{- if .Values.postgres.auth.existingSecret -}}
{{ .Values.postgres.auth.existingSecret }}
{{- else -}}
postgres-auth
{{- end -}}
{{- end -}}

{{ define "trackone.commonLabels" -}}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{/*
Render an image reference from a values map:
- repository: required
- tag: optional (defaults to "latest" when digest is not set)
- digest: optional (if set, takes precedence over tag)
*/}}
{{- define "trackone.image" -}}
{{- $repo := required "image.repository is required" .repository -}}
{{- if .digest -}}
{{- printf "%s@%s" $repo .digest -}}
{{- else -}}
{{- $tag := default "latest" .tag -}}
{{- printf "%s:%s" $repo $tag -}}
{{- end -}}
{{- end -}}
