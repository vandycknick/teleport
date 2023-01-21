{{- define "teleport-kube-agent.config" -}}
{{- $logLevel := (coalesce .Values.logLevel .Values.log.level "INFO") -}}
{{- if .Values.teleportVersionOverride -}}
  {{- $_ := set . "teleportVersion" .Values.teleportVersionOverride -}}
{{- else -}}
  {{- $_ := set . "teleportVersion" .Chart.Version -}}
{{- end -}}
{{- if (ge (semver .teleportVersion).Major 11) }}
version: v3
{{- end }}
teleport:
  join_params:
    method: "{{ .Values.joinParams.method }}"
    token_name: "/etc/teleport-secrets/auth-token"
  {{- if (ge (semver .teleportVersion).Major 11) }}
  proxy_server: {{ required "proxyAddr is required in chart values" .Values.proxyAddr }}
  {{- else }}
  auth_servers: ["{{ required "proxyAddr is required in chart values" .Values.proxyAddr }}"]
  {{- end }}
  {{- if .Values.caPin }}
  ca_pin: {{- toYaml .Values.caPin | nindent 8 }}
  {{- end }}
  log:
    severity: {{ $logLevel }}
    output: {{ .Values.log.output }}
    format:
      output: {{ .Values.log.format }}
      extra_fields: {{ .Values.log.extraFields | toJson }}

kubernetes_service:
  {{- if or (contains "kube" (.Values.roles | toString)) (empty .Values.roles) }}
  enabled: true
  kube_cluster_name: {{ required "kubeClusterName is required in chart values when kube role is enabled, see README" .Values.kubeClusterName }}
    {{- if .Values.labels }}
  labels: {{- toYaml .Values.labels | nindent 8 }}
    {{- end }}
  {{- else }}
  enabled: false
  {{- end }}

app_service:
  {{- if contains "app" (.Values.roles | toString) }}
  enabled: true
  {{- if not (or (.Values.apps) (.Values.appResources)) }}
    {{- fail "at least one of 'apps' and 'appResources' is required in chart values when app role is enabled, see README" }}
  {{- end }}
  {{- if .Values.apps }}
    {{- range $app := .Values.apps }}
      {{- if not (hasKey $app "name") }}
        {{- fail "'name' is required for all 'apps' in chart values when app role is enabled, see README" }}
      {{- end }}
      {{- if not (hasKey $app "uri") }}
        {{- fail "'uri' is required for all 'apps' in chart values when app role is enabled, see README" }}
      {{- end }}
    {{- end }}
  apps:
    {{- toYaml .Values.apps | nindent 8 }}
  {{- end }}
  {{- if .Values.appResources }}
  resources:
    {{- toYaml .Values.appResources | nindent 8 }}
  {{- end }}
  {{- else }}
  enabled: false
  {{- end }}

db_service:
  {{- if contains "db" (.Values.roles | toString) }}
  enabled: true
  {{- if not (or (.Values.awsDatabases) (.Values.azureDatabases) (.Values.databases) (.Values.databaseResources)) }}
    {{- fail "at least one of 'awsDatabases', 'azureDatabases', 'databases' or 'databaseResources' is required in chart values when db role is enabled, see README" }}
  {{- end }}
  {{- if .Values.awsDatabases }}
  aws:
    {{- range $awsDb := .Values.awsDatabases }}
      {{- if not (hasKey $awsDb "types") }}
        {{- fail "'types' is required for all 'awsDatabases' in chart values when key is set and db role is enabled, see README" }}
      {{- end }}
      {{- if not (hasKey $awsDb "regions") }}
        {{- fail "'regions' is required for all 'awsDatabases' in chart values when key is set and db role is enabled, see README" }}
      {{- end }}
      {{- if not (hasKey $awsDb "tags") }}
        {{- fail "'tags' is required for all 'awsDatabases' in chart values when key is set and db role is enabled, see README" }}
      {{- end }}
    {{- end }}
    {{- toYaml .Values.awsDatabases | nindent 6 }}
  {{- end }}
  {{- if .Values.azureDatabases }}
  azure:
    {{- toYaml .Values.azureDatabases | nindent 6 }}
  {{- end}}
  {{- if .Values.databases }}
  databases:
    {{- range $db := .Values.databases }}
      {{- if not (hasKey $db "name") }}
        {{- fail "'name' is required for all 'databases' in chart values when db role is enabled, see README" }}
      {{- end }}
      {{- if not (hasKey $db "uri") }}
        {{- fail "'uri' is required for all 'databases' is required in chart values when db role is enabled, see README" }}
      {{- end }}
      {{- if not (hasKey $db "protocol") }}
        {{- fail "'protocol' is required for all 'databases' in chart values when db role is enabled, see README" }}
      {{- end }}
    {{- end }}
    {{- toYaml .Values.databases | nindent 6 }}
  {{- end }}
  {{- if .Values.databaseResources }}
  resources:
    {{- toYaml .Values.databaseResources | nindent 6 }}
  {{- end }}
{{- else }}
  enabled: false
{{- end }}

auth_service:
  enabled: false
ssh_service:
  enabled: false
proxy_service:
  enabled: false
{{- end -}}
