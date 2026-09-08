{{/* Chart name, overridable. */}}
{{- define "codex-pool.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Fully qualified release name. */}}
{{- define "codex-pool.fullname" -}}
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

{{- define "codex-pool.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "codex-pool.labels" -}}
helm.sh/chart: {{ include "codex-pool.chart" . }}
{{ include "codex-pool.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/component: app
app.kubernetes.io/part-of: codex-pool
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "codex-pool.selectorLabels" -}}
app.kubernetes.io/name: {{ include "codex-pool.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "codex-pool.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "codex-pool.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Fully resolved image reference. A digest always wins; otherwise an explicit
tag; otherwise the chart's appVersion.
*/}}
{{- define "codex-pool.image" -}}
{{- $repo := required "image.repository is required" .Values.image.repository -}}
{{- if .Values.image.digest -}}
{{- if not (hasPrefix "sha256:" .Values.image.digest) -}}
{{- fail "image.digest must be a full manifest digest, e.g. sha256:abc123..." -}}
{{- end -}}
{{- printf "%s@%s" $repo .Values.image.digest -}}
{{- else -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- if not $tag -}}
{{- fail "set image.digest (preferred) or image.tag" -}}
{{- end -}}
{{- printf "%s:%s" $repo $tag -}}
{{- end -}}
{{- end }}

{{/* Name of the PVC actually mounted. */}}
{{- define "codex-pool.pvcName" -}}
{{- if .Values.persistence.existingClaim -}}
{{- .Values.persistence.existingClaim -}}
{{- else -}}
{{- printf "%s-state" (include "codex-pool.fullname" .) -}}
{{- end -}}
{{- end }}
