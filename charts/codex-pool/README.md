# codex-pool Helm chart

Deploys [codex-pool](https://github.com/darvell/codex-pool) on Kubernetes as a
single, stateful instance.

```sh
kubectl create namespace codex-pool

# The chart never creates this Secret; the app exits without it.
kubectl -n codex-pool create secret generic codex-pool-auth \
  --from-literal=pool-auth-encryption-key="$(openssl rand -hex 32)"

helm install codex-pool ./charts/codex-pool -n codex-pool
```

The container image is built and published by
[`.github/workflows/build.yml`](../../.github/workflows/build.yml) to
`ghcr.io/<owner>/codex-pool`. Point `image.repository` at whichever namespace
publishes the image you want to run.

## What it deploys

| Kind | Name | Notes |
|---|---|---|
| `Deployment` | `<release>` | 1 replica, `Recreate`, read-only root filesystem, UID/GID 999 |
| `Service` | `<release>` | `ClusterIP` on 8989 by default |
| `PersistentVolumeClaim` | `<release>-state` | `ReadWriteOnce`, `helm.sh/resource-policy: keep` |
| `ConfigMap` | `<release>-config` | Renders `/app/config.toml` (non-secret settings only) |
| `ServiceAccount` | `<release>` | No API permissions; token not mounted |
| `Ingress` | `<release>` | Optional, off by default |

No `Secret` is ever created by this chart. `auth.existingSecret` must name a
Secret that you own, so that key material never has to live in a values file.

## Fixed topology

`replicaCount`, `replicas`, `autoscaling`, `podDisruptionBudget`, `strategy`,
`persistence.accessMode(s)` and `persistence.enabled: false` all make the chart
**fail to render**, with an explanation. This is deliberate — see
`templates/_guard.tpl`:

* provider credential files under `pool/<provider>/*.json` are read, mutated and
  rewritten with no cross-process lock, so a second writer loses refreshed OAuth
  tokens and can leave a truncated credential file behind;
* pending OAuth login sessions (state + PKCE verifier) live in a process-local
  in-memory map, and the browser redirect has to return to the same process, so
  a second replica breaks account enrolment;
* `data/proxy.db` (BoltDB), `data/analytics.db` (SQLite) and
  `data/usage.duckdb` (DuckDB) are single-writer file databases on one volume.

`Recreate` rather than `RollingUpdate` for the same reason: a surge pod would
also deadlock waiting for the `ReadWriteOnce` volume to detach.

## Values worth knowing

| Value | Default | Notes |
|---|---|---|
| `image.repository` | `ghcr.io/korkin25/codex-pool` | Built by `.github/workflows/build.yml` |
| `image.digest` | `""` | Preferred in production; wins over `tag` |
| `image.tag` | `""` | Falls back to `.Chart.AppVersion` |
| `auth.existingSecret` | `codex-pool-auth` | Required — the app refuses to start Passport without `POOL_AUTH_ENCRYPTION_KEY` |
| `auth.adminTokenKey` | `""` | Optional `ADMIN_TOKEN` in the same Secret. `/metrics` and `/admin/*` stay closed either way |
| `persistence.storageClass` | `""` (cluster default) | Prefer a class with a `Retain` reclaim policy: the volume holds refresh tokens |
| `persistence.size` | `8Gi` | Includes the 64 MiB analytics reserve file the app preallocates |
| `persistence.keepOnDelete` | `true` | Keeps the claim across `helm uninstall` |
| `config.*` | see `values.yaml` | Rendered into `/app/config.toml`; never put secrets here |
| `config.publicURL` | `""` | Set it once the instance has a stable external URL |
| `service.type` | `ClusterIP` | |
| `ingress.enabled` | `false` | Standard `networking.k8s.io/v1` Ingress |

## Container facts this chart depends on

Verified against the image built from this repository, not inferred:

* the default `listen_addr` is `127.0.0.1:8989`, which neither a kubelet probe
  nor a Service endpoint can reach, so the chart always sets
  `PROXY_LISTEN_ADDR=0.0.0.0:<containerPort>`;
* `main.go` loads `config.toml` **relative to the working directory** (`/app`),
  while `CONFIG_PATH` only steers the hot-reload watcher — hence the subPath
  mount at `/app/config.toml` *and* `CONFIG_PATH` pointing at the same file;
* `data/analytics.db` is hardcoded relative to the working directory, so the
  state volume must be mounted at `/app/data`;
* the image runs as `codex` = UID/GID 999 and works with
  `readOnlyRootFilesystem: true` given a writable `/tmp`, because
  `os.CreateTemp("")` spools request bodies.

## Verification

```sh
helm lint charts/codex-pool
helm template codex-pool charts/codex-pool -n codex-pool
```
