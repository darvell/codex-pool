{{/*
codex-pool.guard — refuse to render a topology the application cannot survive.

Why these are not knobs:

  * Provider credential files under pool/<provider>/*.json are read, mutated and
    rewritten with no cross-process lock. Two writers lose refreshed OAuth
    tokens and can leave a truncated credential file behind.
  * Pending OAuth login sessions (state + PKCE verifier) are held in a
    process-local in-memory map. The browser redirect must return to the very
    process that started the login, so any second replica breaks enrolment.
  * BoltDB (data/proxy.db), SQLite (data/analytics.db) and DuckDB
    (data/usage.duckdb) are single-writer file databases on one volume.

The volume is therefore ReadWriteOnce, the Deployment is `Recreate` (RollingUpdate
would run old and new pods together and deadlock on the RWO attach), and the
replica count is the literal 1. Raising any of them is an application change,
not a values change.
*/}}
{{- define "codex-pool.guard" -}}
{{- if hasKey .Values "replicaCount" -}}
{{- fail "codex-pool: replicaCount is not supported. State is file-backed and single-writer; the chart always deploys exactly 1 replica. See templates/_guard.tpl." -}}
{{- end -}}
{{- if hasKey .Values "replicas" -}}
{{- fail "codex-pool: replicas is not supported. State is file-backed and single-writer; the chart always deploys exactly 1 replica. See templates/_guard.tpl." -}}
{{- end -}}
{{- if hasKey .Values "autoscaling" -}}
{{- fail "codex-pool: autoscaling is not supported. A HorizontalPodAutoscaler would corrupt pooled credentials and orphan in-flight OAuth logins. See templates/_guard.tpl." -}}
{{- end -}}
{{- if hasKey .Values "podDisruptionBudget" -}}
{{- fail "codex-pool: podDisruptionBudget is not supported for a single-replica Recreate workload." -}}
{{- end -}}
{{- if hasKey .Values.persistence "accessModes" -}}
{{- fail "codex-pool: persistence.accessModes is not supported. The state volume is always ReadWriteOnce. See templates/_guard.tpl." -}}
{{- end -}}
{{- if hasKey .Values.persistence "accessMode" -}}
{{- fail "codex-pool: persistence.accessMode is not supported. The state volume is always ReadWriteOnce. See templates/_guard.tpl." -}}
{{- end -}}
{{- if hasKey .Values "strategy" -}}
{{- fail "codex-pool: strategy is not supported. The Deployment is always Recreate so the RWO volume is released before the replacement pod starts." -}}
{{- end -}}
{{- if not .Values.persistence.enabled -}}
{{- fail "codex-pool: persistence.enabled=false would put pooled credentials, OAuth refresh tokens and usage history on the pod's ephemeral filesystem." -}}
{{- end -}}
{{- end }}
