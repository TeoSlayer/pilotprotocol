{{/*
Return the namespace to use for all resources.
Precedence: .Values.namespace → .Release.Namespace
*/}}
{{- define "pilot-integration.namespace" -}}
{{- default .Release.Namespace .Values.namespace -}}
{{- end -}}

{{/*
Common labels applied to every Job.
*/}}
{{- define "pilot-integration.labels" -}}
app.kubernetes.io/name: pilot-integration
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: pilot-protocol
{{- end -}}

{{/*
Match a test's name against the .Values.only filter.
Returns "true" if the test should run.
*/}}
{{- define "pilot-integration.shouldRun" -}}
{{- $only := .only -}}
{{- $name := .name -}}
{{- $script := .script -}}
{{- if not $only -}}
true
{{- else if eq $only $name -}}
true
{{- else if eq $only (trimSuffix ".sh" $script) -}}
true
{{- else if hasPrefix (trimSuffix "*" $only) $name -}}
{{- if hasSuffix "*" $only -}}
true
{{- end -}}
{{- end -}}
{{- end -}}
