# intelowl

A Helm chart for deploying IntelOwl - Open Source Intelligence Platform

![Version: 1.0.0](https://img.shields.io/badge/Version-1.0.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: v6.5.1](https://img.shields.io/badge/AppVersion-v6.5.1-informational?style=flat-square)

## Prerequisites

- Kubernetes 1.25+
- Helm 3.8+
- PV provisioner support (for persistent volumes)
- StorageClass with ReadWriteMany access mode (for shared volumes)
- [CloudNative-PG Operator](https://cloudnative-pg.io/) (for internal PostgreSQL, included as optional subchart or install separately)
- [Redis](https://github.com/cloudpirates/helm-charts) (included as subchart dependency, for broker/cache)
- [RabbitMQ](https://github.com/cloudpirates/helm-charts) (optional subchart dependency, alternative broker to Redis)
- [ECK Operator](https://www.elastic.co/guide/en/cloud-on-k8s/current/k8s-overview.html) (optional, for Elasticsearch/Kibana)
- [Prometheus Operator CRDs](https://github.com/prometheus-operator/prometheus-operator) (optional, for ServiceMonitor/PodMonitor)

### CloudNative-PG Operator (Required for internal PostgreSQL)

The chart uses CloudNative-PG for PostgreSQL. Install the operator before deploying:

```bash
# Add the CNPG Helm repository
helm repo add cnpg https://cloudnative-pg.github.io/charts
helm repo update

# Install the operator
helm install cnpg cnpg/cloudnative-pg -n cnpg-system --create-namespace
```

Alternatively, enable operator installation via the chart:

```bash
helm install intelowl ./intelowl-helm --set postgresql.operator.enabled=true
```

### Gateway API (Required for Gateway networking type)

If using Gateway API (default), install the CRDs and a Gateway provider:

```bash
# Install Gateway API CRDs
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.0/standard-install.yaml

# Install NGINX Gateway Fabric (default provider)
helm install ngf oci://ghcr.io/nginx/charts/nginx-gateway-fabric \
  -n nginx-gateway --create-namespace
```

Supported Gateway providers:

- `nginx-gateway-fabric` (default)
- `envoy-gateway`
- `istio`
- `kong`
- `traefik`

### ECK Operator (Optional - for Elasticsearch/Kibana)

If you want to enable Elasticsearch for analysis results indexing and Kibana for visualization:

```bash
# Add the Elastic Helm repository
helm repo add elastic https://helm.elastic.co
helm repo update

# Install the ECK operator
helm install elastic-operator elastic/eck-operator -n elastic-system --create-namespace
```

Alternatively, the ECK operator can be installed automatically by enabling it as a chart dependency:

```yaml
elasticsearch:
  enabled: true
  operator:
    enabled: true  # installs ECK operator as a subchart dependency
```

### Prometheus CRDs (Optional - for metrics/monitoring)

If you enable `metrics.serviceMonitor` or `metrics.podMonitor`, the [Prometheus Operator](https://github.com/prometheus-operator/prometheus-operator) CRDs must be installed **before** deploying the chart, otherwise Helm will fail with `no matches for kind "ServiceMonitor"` or `"PodMonitor"`.

```bash
# Option A: Install the full kube-prometheus-stack (includes CRDs + Prometheus + Grafana)
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm install kube-prometheus prometheus-community/kube-prometheus-stack -n monitoring --create-namespace

# Option B: Install only the CRDs (if you manage Prometheus separately)
kubectl apply -f https://raw.githubusercontent.com/prometheus-operator/prometheus-operator/main/example/prometheus-operator-crd/monitoring.coreos.com_servicemonitors.yaml
kubectl apply -f https://raw.githubusercontent.com/prometheus-operator/prometheus-operator/main/example/prometheus-operator-crd/monitoring.coreos.com_podmonitors.yaml
```

## Installation

### Install from source

```bash
cd intelowl-helm
helm install intelowl . -f examples/minimal.yaml -n intelowl --create-namespace
```

### Generate Django Secret Key

```bash
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```

### Example installations

```bash
# Basic installation with Gateway API (default)
helm install intelowl . \
  --namespace intelowl \
  --create-namespace \
  --set app.django.secretKey="your-secret-key"

# With traditional Ingress
helm install intelowl . \
  --namespace intelowl \
  --create-namespace \
  --set app.django.secretKey="your-secret-key" \
  --set networking.type=ingress \
  --set networking.ingress.enabled=true \
  --set networking.ingress.hosts[0].host=intelowl.example.com

# Production with HA PostgreSQL (3 instances)
helm install intelowl . \
  --namespace intelowl \
  --create-namespace \
  --set app.django.secretKey="your-secret-key" \
  --set postgresql.instances=3 \
  --set postgresql.synchronous.enabled=true \
  --set multiQueue.enabled=true \
  --set uwsgi.autoscaling.enabled=true

# With RabbitMQ as message broker (instead of Redis)
helm install intelowl . \
  --namespace intelowl \
  --create-namespace \
  --set app.django.secretKey="your-secret-key" \
  --set broker.type=rabbitmq \
  --set broker.rabbitmq.internal=true \
  --set rabbitmq.enabled=true

# With Elasticsearch and Kibana
helm install intelowl . \
  --namespace intelowl \
  --create-namespace \
  --set app.django.secretKey="your-secret-key" \
  --set elasticsearch.enabled=true \
  --set elasticsearch.kibana.enabled=true

# With automatic superuser creation
helm install intelowl . \
  --namespace intelowl \
  --create-namespace \
  --set app.django.secretKey="your-secret-key" \
  --set superuser.enabled=true \
  --set superuser.username=admin \
  --set superuser.email=admin@example.com \
  --set superuser.password="your-strong-password"
```

## Getting Started

After installation, follow these steps to get IntelOwl up and running:

### 1. Wait for all pods to be ready

```bash
kubectl get pods -n intelowl -w
```

### 2. Create an admin superuser

This step is **required** to access IntelOwl.

**Option A: Automatic creation (recommended)**

Enable automatic superuser creation in your values:

```yaml
superuser:
  enabled: true
  username: admin
  email: admin@example.com
  password: "your-strong-password"  # auto-generated if empty
```

**Option B: Manual creation**

```bash
kubectl exec -it deploy/intelowl-uwsgi -n intelowl -- python manage.py createsuperuser
```

You will be prompted to enter a username, email, and password.

### 3. Access IntelOwl

**Using port-forward (development/testing):**

```bash
kubectl port-forward svc/intelowl-nginx 8080:80 -n intelowl
```

Then open http://localhost:8080 in your browser.

**Using Gateway API or Ingress (production):**

Configure your DNS or `/etc/hosts` to point to the Gateway/Ingress IP address.

### 4. Login

Navigate to the login page and use the superuser credentials you created in step 2.

### 5. Configure analyzers

After logging in, go to the admin panel (`/admin`) to configure:

- API keys for external services (VirusTotal, OTX, etc.)
- Enable/disable specific analyzers
- Create additional user accounts

## Architecture

```mermaid
graph TB
    Gateway["Gateway / Ingress"]

    subgraph Web["Web layer"]
        Nginx
    end

    subgraph App["Application layer"]
        uWSGI["uWSGI (Django)"]
        Daphne["Daphne (WebSocket)"]
        CeleryBeat["Celery Beat"]
        Workers["Celery Workers"]
    end

    subgraph Data["Data layer"]
        PostgreSQL["PostgreSQL (CNPG)"]
        Redis["Redis / RabbitMQ"]
    end

    subgraph Search["Search & Analytics"]
        Elasticsearch["Elasticsearch (ECK)"]
        Kibana
    end

    Gateway --> Nginx
    Nginx --> uWSGI
    Nginx --> Daphne

    uWSGI --> PostgreSQL
    uWSGI --> Redis
    uWSGI --> Elasticsearch
    Daphne --> Redis
    Workers --> PostgreSQL
    Workers --> Redis
    Workers --> Elasticsearch
    CeleryBeat --> Redis
    Kibana --> Elasticsearch
```

## Persistence

The chart provisions three PVCs by default:

| PVC              | Purpose                   | Default Size |
| ---------------- | ------------------------- | ------------ |
| `generic-logs`   | Application logs          | 10Gi         |
| `shared-files`   | Analyzer results, uploads | 20Gi         |
| `static-content` | Django static files       | 5Gi          |

All PVCs require `ReadWriteMany` access mode for multi-replica deployments.

## Upgrading

```bash
helm upgrade intelowl . \
  --namespace intelowl \
  --reuse-values
```

## Uninstalling

```bash
helm uninstall intelowl --namespace intelowl
```

**Note:** PVCs are not deleted by default. To remove them:

```bash
kubectl delete pvc -l app.kubernetes.io/instance=intelowl -n intelowl
```

## Troubleshooting

### Check pod status

```bash
kubectl get pods -n intelowl -l app.kubernetes.io/instance=intelowl
```

### View logs

```bash
# uWSGI logs
kubectl logs -f deploy/intelowl-uwsgi -n intelowl

# Celery worker logs
kubectl logs -f deploy/intelowl-celery-worker-default -n intelowl

# Migration job logs
kubectl logs -l app.kubernetes.io/component=migration -n intelowl
```

### Run Django management commands

```bash
kubectl exec -it deploy/intelowl-uwsgi -n intelowl -- python manage.py <command>
```

### Create superuser

```bash
kubectl exec -it deploy/intelowl-uwsgi -n intelowl -- python manage.py createsuperuser
```

### Common issues

**Pods stuck in Pending:**

- Check if PVCs are bound: `kubectl get pvc -n intelowl`
- Verify StorageClass supports ReadWriteMany

**Database connection errors:**

- Ensure CloudNative-PG operator is installed
- Check PostgreSQL cluster status: `kubectl get cluster -n intelowl`

**Gateway/Ingress not working:**

- Verify Gateway API CRDs are installed (for Gateway type)
- Check Gateway controller is running
- Verify GatewayClass exists: `kubectl get gatewayclass`

**Elasticsearch issues:**

- Ensure ECK operator is installed: `kubectl get pods -n elastic-system`
- Check Elasticsearch cluster health: `kubectl get elasticsearch -n intelowl`
- Check Kibana status: `kubectl get kibana -n intelowl`
- Elasticsearch needs at least 2GiB of free memory per node

**Cannot create superuser:**

- Ensure all pods are running: `kubectl get pods -n intelowl`
- Check uWSGI pod logs for errors
- If using automatic creation, check the superuser job: `kubectl logs -l app.kubernetes.io/component=superuser -n intelowl`

## Requirements

Kubernetes: `>=1.25.0-0`

| Repository | Name | Version |
|------------|------|---------|
| https://cloudnative-pg.github.io/charts | cnpg(cloudnative-pg) | 0.27.* |
| https://helm.elastic.co | eck(eck-operator) | 3.3.* |
| oci://registry-1.docker.io/cloudpirates | rabbitmq(rabbitmq) | 0.18.* |
| oci://registry-1.docker.io/cloudpirates | redis(redis) | 0.26.* |

## Values

### Global parameters

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| global.imagePullSecrets | list | `[]` | Global Docker registry secret names as an array |
| global.imageRegistry | string | `""` | Global Docker image registry |
| global.storageClass | string | `""` | Global StorageClass for Persistent Volume(s) |

### Common parameters

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| fullnameOverride | string | `""` | String to fully override intelowl.fullname |
| nameOverride | string | `""` | String to partially override intelowl.fullname |

### Application parameters

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| app.baseUrl | string | `""` | Base URL for the application (used for CORS and absolute URLs) |
| app.defaultTimeout | int | `300` | Default timeout for analyzers in seconds |
| app.django.allowedHosts | string | `"*"` | Django allowed hosts (comma-separated) |
| app.django.debug | bool | `false` | Enable Django debug mode (never enable in production) |
| app.django.existingSecret | string | `""` | Use existing secret for Django secret key (key: django-secret) |
| app.django.secretKey | string | `""` | Django secret key (required). Generate with: python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())" |
| app.email.defaultEmail | string | `""` | Default recipient email address |
| app.email.defaultFromEmail | string | `""` | Default sender email address |
| app.email.enabled | bool | `false` | Enable email notifications |
| app.email.existingSecret | string | `""` | Use existing secret for SMTP password (key: email-password) |
| app.email.host | string | `""` | SMTP server host |
| app.email.hostPassword | string | `""` | SMTP password |
| app.email.hostUser | string | `""` | SMTP username |
| app.email.port | int | `587` | SMTP server port |
| app.email.useSsl | bool | `false` | Use SSL for SMTP |
| app.email.useTls | bool | `true` | Use TLS for SMTP |
| app.httpsEnabled | bool | `false` | Enable HTTPS security headers (set to true when TLS is terminated at ingress/gateway) |
| app.logLevel | string | `"INFO"` | Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL) |
| app.oldJobsRetentionDays | int | `14` | Number of days to retain old jobs (set to 0 to disable) |
| app.slack.defaultChannel | string | `""` | Default Slack channel for notifications |
| app.slack.enabled | bool | `false` | Enable Slack notifications |
| app.slack.existingSecret | string | `""` | Use existing secret for Slack token (key: slack-token) |
| app.slack.token | string | `""` | Slack API token |
| app.version | string | `"v6.5.1"` | IntelOwl application version |

### Database parameters

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| database.external.existingSecret | string | `""` | Use existing secret for database password (key: db-password) |
| database.external.host | string | `""` | External database host |
| database.external.name | string | `"intel_owl_db"` | External database name |
| database.external.password | string | `""` | External database password |
| database.external.port | int | `5432` | External database port |
| database.external.sslMode | string | `"prefer"` | SSL mode for PostgreSQL connection |
| database.external.user | string | `"intelowl"` | External database user |
| database.internal | bool | `true` | Use internal PostgreSQL (CloudNative-PG) subchart |

### Broker parameters

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| broker.rabbitmq.external.existingSecret | string | `""` | Use existing secret for RabbitMQ password (key: rabbitmq-password) |
| broker.rabbitmq.external.host | string | `""` | External RabbitMQ host |
| broker.rabbitmq.external.password | string | `""` | External RabbitMQ password |
| broker.rabbitmq.external.port | int | `5672` | External RabbitMQ port |
| broker.rabbitmq.external.user | string | `"guest"` | External RabbitMQ user |
| broker.rabbitmq.external.vhost | string | `"/"` | External RabbitMQ virtual host |
| broker.rabbitmq.internal | bool | `false` | Use internal RabbitMQ subchart |
| broker.redis.external.db | int | `0` | Redis database number |
| broker.redis.external.existingSecret | string | `""` | Use existing secret for Redis password (key: redis-password) |
| broker.redis.external.host | string | `""` | External Redis host |
| broker.redis.external.password | string | `""` | External Redis password |
| broker.redis.external.port | int | `6379` | External Redis port |
| broker.redis.internal | bool | `true` | Use internal Redis subchart |
| broker.sqs.accessKeyId | string | `""` | AWS access key ID |
| broker.sqs.existingSecret | string | `""` | Use existing secret for AWS credentials |
| broker.sqs.region | string | `""` | AWS region for SQS |
| broker.sqs.secretAccessKey | string | `""` | AWS secret access key |
| broker.type | string | `"redis"` | Broker type: redis, rabbitmq, or sqs |

### Storage parameters

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| storage.genericLogs.accessModes | list | `["ReadWriteMany"]` | Access modes for generic logs PVC |
| storage.genericLogs.size | string | `"10Gi"` | Storage size for generic logs |
| storage.genericLogs.storageClass | string | `""` | Storage class for generic logs (uses global.storageClass if empty) |
| storage.localStorage | bool | `true` | Use local storage (PVCs). Set to false for cloud storage (S3) |
| storage.s3.accessKeyId | string | `""` | AWS access key ID |
| storage.s3.bucket | string | `""` | S3 bucket name |
| storage.s3.enabled | bool | `false` | Enable S3 storage |
| storage.s3.endpoint | string | `""` | S3 endpoint URL (for S3-compatible storage like MinIO) |
| storage.s3.existingSecret | string | `""` | Use existing secret for S3 credentials |
| storage.s3.region | string | `""` | AWS region |
| storage.s3.secretAccessKey | string | `""` | AWS secret access key |
| storage.sharedFiles.accessModes | list | `["ReadWriteMany"]` | Access modes for shared files PVC |
| storage.sharedFiles.size | string | `"20Gi"` | Storage size for shared files |
| storage.sharedFiles.storageClass | string | `""` | Storage class for shared files (uses global.storageClass if empty) |
| storage.staticContent.accessModes | list | `["ReadWriteMany"]` | Access modes for static content PVC |
| storage.staticContent.size | string | `"5Gi"` | Storage size for static content |
| storage.staticContent.storageClass | string | `""` | Storage class for static content (uses global.storageClass if empty) |

### uWSGI parameters

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| uwsgi.affinity | object | `{}` | Affinity rules for uWSGI pods |
| uwsgi.autoscaling.enabled | bool | `false` | Enable Horizontal Pod Autoscaler for uWSGI |
| uwsgi.autoscaling.maxReplicas | int | `10` | Maximum number of replicas |
| uwsgi.autoscaling.minReplicas | int | `2` | Minimum number of replicas |
| uwsgi.autoscaling.targetCPUUtilizationPercentage | int | `80` | Target CPU utilization percentage |
| uwsgi.autoscaling.targetMemoryUtilizationPercentage | int | `80` | Target memory utilization percentage |
| uwsgi.extraEnvVars | list | `[]` | Additional environment variables for uWSGI |
| uwsgi.extraVolumeMounts | list | `[]` | Additional volume mounts for uWSGI |
| uwsgi.extraVolumes | list | `[]` | Additional volumes for uWSGI |
| uwsgi.image.pullPolicy | string | `"IfNotPresent"` | uWSGI image pull policy |
| uwsgi.image.repository | string | `"intelowlproject/intelowl"` | uWSGI image repository |
| uwsgi.image.tag | string | `""` | uWSGI image tag (defaults to app.version) |
| uwsgi.livenessProbe.enabled | bool | `true` | Enable liveness probe |
| uwsgi.livenessProbe.failureThreshold | int | `6` | Failure threshold |
| uwsgi.livenessProbe.initialDelaySeconds | int | `10` | Initial delay seconds |
| uwsgi.livenessProbe.periodSeconds | int | `10` | Period seconds |
| uwsgi.livenessProbe.successThreshold | int | `1` | Success threshold |
| uwsgi.livenessProbe.timeoutSeconds | int | `5` | Timeout seconds |
| uwsgi.nodeSelector | object | `{}` | Node selector for uWSGI pods |
| uwsgi.pdb.enabled | bool | `true` | Enable Pod Disruption Budget for uWSGI |
| uwsgi.pdb.minAvailable | int | `1` | Minimum available pods |
| uwsgi.readinessProbe.enabled | bool | `true` | Enable readiness probe |
| uwsgi.readinessProbe.failureThreshold | int | `6` | Failure threshold |
| uwsgi.readinessProbe.initialDelaySeconds | int | `5` | Initial delay seconds |
| uwsgi.readinessProbe.periodSeconds | int | `10` | Period seconds |
| uwsgi.readinessProbe.successThreshold | int | `1` | Success threshold |
| uwsgi.readinessProbe.timeoutSeconds | int | `5` | Timeout seconds |
| uwsgi.replicaCount | int | `2` | Number of uWSGI replicas |
| uwsgi.resources.limits.cpu | string | `"2"` | CPU limit for uWSGI |
| uwsgi.resources.limits.memory | string | `"4Gi"` | Memory limit for uWSGI |
| uwsgi.resources.requests.cpu | string | `"500m"` | CPU request for uWSGI |
| uwsgi.resources.requests.memory | string | `"1Gi"` | Memory request for uWSGI |
| uwsgi.service.port | int | `8001` | uWSGI service port |
| uwsgi.service.type | string | `"ClusterIP"` | uWSGI service type |
| uwsgi.startupProbe.enabled | bool | `true` | Enable startup probe |
| uwsgi.startupProbe.failureThreshold | int | `30` | Failure threshold |
| uwsgi.startupProbe.initialDelaySeconds | int | `30` | Initial delay seconds |
| uwsgi.startupProbe.periodSeconds | int | `10` | Period seconds |
| uwsgi.startupProbe.successThreshold | int | `1` | Success threshold |
| uwsgi.startupProbe.timeoutSeconds | int | `5` | Timeout seconds |
| uwsgi.tolerations | list | `[]` | Tolerations for uWSGI pods |

### Daphne parameters

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| daphne.affinity | object | `{}` | Affinity rules for Daphne pods |
| daphne.enabled | bool | `true` | Enable Daphne service |
| daphne.extraEnvVars | list | `[]` | Additional environment variables for Daphne |
| daphne.extraVolumeMounts | list | `[]` | Additional volume mounts for Daphne |
| daphne.extraVolumes | list | `[]` | Additional volumes for Daphne |
| daphne.image.pullPolicy | string | `"IfNotPresent"` | Daphne image pull policy |
| daphne.image.repository | string | `"intelowlproject/intelowl"` | Daphne image repository |
| daphne.image.tag | string | `""` | Daphne image tag (defaults to app.version) |
| daphne.livenessProbe.enabled | bool | `true` | Enable liveness probe |
| daphne.livenessProbe.failureThreshold | int | `6` | Failure threshold |
| daphne.livenessProbe.initialDelaySeconds | int | `10` | Initial delay seconds |
| daphne.livenessProbe.periodSeconds | int | `10` | Period seconds |
| daphne.livenessProbe.successThreshold | int | `1` | Success threshold |
| daphne.livenessProbe.timeoutSeconds | int | `5` | Timeout seconds |
| daphne.nodeSelector | object | `{}` | Node selector for Daphne pods |
| daphne.pdb.enabled | bool | `true` | Enable Pod Disruption Budget for Daphne |
| daphne.pdb.minAvailable | int | `1` | Minimum available pods |
| daphne.readinessProbe.enabled | bool | `true` | Enable readiness probe |
| daphne.readinessProbe.failureThreshold | int | `6` | Failure threshold |
| daphne.readinessProbe.initialDelaySeconds | int | `5` | Initial delay seconds |
| daphne.readinessProbe.periodSeconds | int | `10` | Period seconds |
| daphne.readinessProbe.successThreshold | int | `1` | Success threshold |
| daphne.readinessProbe.timeoutSeconds | int | `5` | Timeout seconds |
| daphne.replicaCount | int | `2` | Number of Daphne replicas |
| daphne.resources.limits.cpu | string | `"1"` | CPU limit for Daphne |
| daphne.resources.limits.memory | string | `"2Gi"` | Memory limit for Daphne |
| daphne.resources.requests.cpu | string | `"250m"` | CPU request for Daphne |
| daphne.resources.requests.memory | string | `"512Mi"` | Memory request for Daphne |
| daphne.service.port | int | `8011` | Daphne service port |
| daphne.service.type | string | `"ClusterIP"` | Daphne service type |
| daphne.startupProbe.enabled | bool | `true` | Enable startup probe |
| daphne.startupProbe.failureThreshold | int | `12` | Failure threshold |
| daphne.startupProbe.initialDelaySeconds | int | `10` | Initial delay seconds |
| daphne.startupProbe.periodSeconds | int | `5` | Period seconds |
| daphne.startupProbe.successThreshold | int | `1` | Success threshold |
| daphne.startupProbe.timeoutSeconds | int | `3` | Timeout seconds |
| daphne.tolerations | list | `[]` | Tolerations for Daphne pods |

### Nginx parameters

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| nginx.affinity | object | `{}` | Affinity rules for Nginx pods |
| nginx.extraEnvVars | list | `[]` | Additional environment variables for Nginx |
| nginx.extraVolumeMounts | list | `[]` | Additional volume mounts for Nginx |
| nginx.extraVolumes | list | `[]` | Additional volumes for Nginx |
| nginx.image.pullPolicy | string | `"IfNotPresent"` | Nginx image pull policy |
| nginx.image.repository | string | `"intelowlproject/intelowl_nginx"` | Nginx image repository |
| nginx.image.tag | string | `""` | Nginx image tag (defaults to app.version) |
| nginx.livenessProbe.enabled | bool | `true` | Enable liveness probe |
| nginx.livenessProbe.failureThreshold | int | `6` | Failure threshold |
| nginx.livenessProbe.initialDelaySeconds | int | `10` | Initial delay seconds |
| nginx.livenessProbe.periodSeconds | int | `10` | Period seconds |
| nginx.livenessProbe.successThreshold | int | `1` | Success threshold |
| nginx.livenessProbe.timeoutSeconds | int | `5` | Timeout seconds |
| nginx.nodeSelector | object | `{}` | Node selector for Nginx pods |
| nginx.pdb.enabled | bool | `true` | Enable Pod Disruption Budget for Nginx |
| nginx.pdb.minAvailable | int | `1` | Minimum available pods |
| nginx.readinessProbe.enabled | bool | `true` | Enable readiness probe |
| nginx.readinessProbe.failureThreshold | int | `6` | Failure threshold |
| nginx.readinessProbe.initialDelaySeconds | int | `5` | Initial delay seconds |
| nginx.readinessProbe.periodSeconds | int | `10` | Period seconds |
| nginx.readinessProbe.successThreshold | int | `1` | Success threshold |
| nginx.readinessProbe.timeoutSeconds | int | `5` | Timeout seconds |
| nginx.replicaCount | int | `2` | Number of Nginx replicas |
| nginx.resources.limits.cpu | string | `"500m"` | CPU limit for Nginx |
| nginx.resources.limits.memory | string | `"512Mi"` | Memory limit for Nginx |
| nginx.resources.requests.cpu | string | `"100m"` | CPU request for Nginx |
| nginx.resources.requests.memory | string | `"128Mi"` | Memory request for Nginx |
| nginx.service.httpsPort | int | `443` | Nginx HTTPS port |
| nginx.service.port | int | `80` | Nginx HTTP port |
| nginx.service.type | string | `"ClusterIP"` | Nginx service type |
| nginx.startupProbe.enabled | bool | `true` | Enable startup probe |
| nginx.startupProbe.failureThreshold | int | `12` | Failure threshold |
| nginx.startupProbe.initialDelaySeconds | int | `5` | Initial delay seconds |
| nginx.startupProbe.periodSeconds | int | `5` | Period seconds |
| nginx.startupProbe.successThreshold | int | `1` | Success threshold |
| nginx.startupProbe.timeoutSeconds | int | `3` | Timeout seconds |
| nginx.tolerations | list | `[]` | Tolerations for Nginx pods |

### Celery Beat parameters

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| celeryBeat.affinity | object | `{}` | Affinity rules for Celery Beat pod |
| celeryBeat.extraEnvVars | list | `[]` | Additional environment variables for Celery Beat |
| celeryBeat.extraVolumeMounts | list | `[]` | Additional volume mounts for Celery Beat |
| celeryBeat.extraVolumes | list | `[]` | Additional volumes for Celery Beat |
| celeryBeat.image.pullPolicy | string | `"IfNotPresent"` | Celery Beat image pull policy |
| celeryBeat.image.repository | string | `"intelowlproject/intelowl"` | Celery Beat image repository |
| celeryBeat.image.tag | string | `""` | Celery Beat image tag (defaults to app.version) |
| celeryBeat.nodeSelector | object | `{}` | Node selector for Celery Beat pod |
| celeryBeat.resources.limits.cpu | string | `"250m"` | CPU limit for Celery Beat |
| celeryBeat.resources.limits.memory | string | `"512Mi"` | Memory limit for Celery Beat |
| celeryBeat.resources.requests.cpu | string | `"100m"` | CPU request for Celery Beat |
| celeryBeat.resources.requests.memory | string | `"256Mi"` | Memory request for Celery Beat |
| celeryBeat.tolerations | list | `[]` | Tolerations for Celery Beat pod |

### Celery Worker parameters

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| celeryWorkerDefault.affinity | object | `{}` | Affinity rules for Celery Worker pods |
| celeryWorkerDefault.autoscaling.enabled | bool | `false` | Enable Horizontal Pod Autoscaler for Celery Worker |
| celeryWorkerDefault.autoscaling.maxReplicas | int | `10` | Maximum number of replicas |
| celeryWorkerDefault.autoscaling.minReplicas | int | `2` | Minimum number of replicas |
| celeryWorkerDefault.autoscaling.targetCPUUtilizationPercentage | int | `80` | Target CPU utilization percentage |
| celeryWorkerDefault.autoscaling.targetMemoryUtilizationPercentage | int | `80` | Target memory utilization percentage |
| celeryWorkerDefault.concurrency | int | `4` | Celery concurrency (number of worker processes per pod) |
| celeryWorkerDefault.extraEnvVars | list | `[]` | Additional environment variables for Celery Worker |
| celeryWorkerDefault.extraVolumeMounts | list | `[]` | Additional volume mounts for Celery Worker |
| celeryWorkerDefault.extraVolumes | list | `[]` | Additional volumes for Celery Worker |
| celeryWorkerDefault.image.pullPolicy | string | `"IfNotPresent"` | Celery Worker image pull policy |
| celeryWorkerDefault.image.repository | string | `"intelowlproject/intelowl"` | Celery Worker image repository |
| celeryWorkerDefault.image.tag | string | `""` | Celery Worker image tag (defaults to app.version) |
| celeryWorkerDefault.nodeSelector | object | `{}` | Node selector for Celery Worker pods |
| celeryWorkerDefault.pdb.enabled | bool | `true` | Enable Pod Disruption Budget for Celery Worker |
| celeryWorkerDefault.pdb.minAvailable | int | `1` | Minimum available pods |
| celeryWorkerDefault.replicaCount | int | `2` | Number of Celery Worker replicas |
| celeryWorkerDefault.resources.limits.cpu | string | `"2"` | CPU limit for Celery Worker |
| celeryWorkerDefault.resources.limits.memory | string | `"4Gi"` | Memory limit for Celery Worker |
| celeryWorkerDefault.resources.requests.cpu | string | `"500m"` | CPU request for Celery Worker |
| celeryWorkerDefault.resources.requests.memory | string | `"1Gi"` | Memory request for Celery Worker |
| celeryWorkerDefault.terminationGracePeriodSeconds | int | `180` | Termination grace period in seconds (allow tasks to complete) |
| celeryWorkerDefault.tolerations | list | `[]` | Tolerations for Celery Worker pods |

### Multi-queue workers parameters

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| multiQueue.enabled | bool | `false` | Enable multi-queue workers for better resource isolation |
| multiQueue.workerIngestor.affinity | object | `{}` | Affinity rules |
| multiQueue.workerIngestor.concurrency | int | `2` | Worker concurrency |
| multiQueue.workerIngestor.enabled | bool | `true` | Enable ingestor worker |
| multiQueue.workerIngestor.nodeSelector | object | `{}` | Node selector |
| multiQueue.workerIngestor.replicaCount | int | `1` | Number of replicas |
| multiQueue.workerIngestor.resources.limits.cpu | string | `"1"` | CPU limit |
| multiQueue.workerIngestor.resources.limits.memory | string | `"2Gi"` | Memory limit |
| multiQueue.workerIngestor.resources.requests.cpu | string | `"250m"` | CPU request |
| multiQueue.workerIngestor.resources.requests.memory | string | `"512Mi"` | Memory request |
| multiQueue.workerIngestor.terminationGracePeriodSeconds | int | `180` | Termination grace period |
| multiQueue.workerIngestor.tolerations | list | `[]` | Tolerations |
| multiQueue.workerLocal.affinity | object | `{}` | Affinity rules |
| multiQueue.workerLocal.concurrency | int | `2` | Worker concurrency |
| multiQueue.workerLocal.enabled | bool | `true` | Enable local queue worker |
| multiQueue.workerLocal.nodeSelector | object | `{}` | Node selector |
| multiQueue.workerLocal.replicaCount | int | `1` | Number of replicas |
| multiQueue.workerLocal.resources.limits.cpu | string | `"1"` | CPU limit |
| multiQueue.workerLocal.resources.limits.memory | string | `"2Gi"` | Memory limit |
| multiQueue.workerLocal.resources.requests.cpu | string | `"250m"` | CPU request |
| multiQueue.workerLocal.resources.requests.memory | string | `"512Mi"` | Memory request |
| multiQueue.workerLocal.terminationGracePeriodSeconds | int | `180` | Termination grace period |
| multiQueue.workerLocal.tolerations | list | `[]` | Tolerations |
| multiQueue.workerLong.affinity | object | `{}` | Affinity rules |
| multiQueue.workerLong.concurrency | int | `2` | Worker concurrency |
| multiQueue.workerLong.enabled | bool | `true` | Enable long-running tasks worker |
| multiQueue.workerLong.nodeSelector | object | `{}` | Node selector |
| multiQueue.workerLong.replicaCount | int | `1` | Number of replicas |
| multiQueue.workerLong.resources.limits.cpu | string | `"2"` | CPU limit |
| multiQueue.workerLong.resources.limits.memory | string | `"4Gi"` | Memory limit |
| multiQueue.workerLong.resources.requests.cpu | string | `"500m"` | CPU request |
| multiQueue.workerLong.resources.requests.memory | string | `"1Gi"` | Memory request |
| multiQueue.workerLong.terminationGracePeriodSeconds | int | `600` | Termination grace period (longer for long tasks) |
| multiQueue.workerLong.tolerations | list | `[]` | Tolerations |

### Flower parameters

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| flower.affinity | object | `{}` | Affinity rules for Flower pod |
| flower.auth.enabled | bool | `true` | Enable basic authentication |
| flower.auth.existingSecret | string | `""` | Use existing secret for password (key: flower-password) |
| flower.auth.password | string | `""` | Password for basic auth (auto-generated if empty) |
| flower.auth.username | string | `"admin"` | Username for basic auth |
| flower.enabled | bool | `false` | Enable Flower dashboard |
| flower.image.pullPolicy | string | `"IfNotPresent"` | Flower image pull policy |
| flower.image.repository | string | `"mher/flower"` | Flower image repository |
| flower.image.tag | string | `"2.0"` | Flower image tag |
| flower.ingress.annotations | object | `{}` | Ingress annotations |
| flower.ingress.className | string | `""` | Ingress class name |
| flower.ingress.enabled | bool | `false` | Enable Ingress for Flower |
| flower.ingress.hosts | list | `[{"host":"flower.intelowl.local","paths":[{"path":"/","pathType":"Prefix"}]}]` | Ingress hosts |
| flower.ingress.tls | list | `[]` | TLS configuration |
| flower.nodeSelector | object | `{}` | Node selector for Flower pod |
| flower.replicaCount | int | `1` | Number of Flower replicas |
| flower.resources.limits.cpu | string | `"500m"` | CPU limit for Flower |
| flower.resources.limits.memory | string | `"512Mi"` | Memory limit for Flower |
| flower.resources.requests.cpu | string | `"100m"` | CPU request for Flower |
| flower.resources.requests.memory | string | `"256Mi"` | Memory request for Flower |
| flower.service.port | int | `5555` | Flower service port |
| flower.service.type | string | `"ClusterIP"` | Flower service type |
| flower.tolerations | list | `[]` | Tolerations for Flower pod |

### Integrations parameters

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| integrations.bbot.enabled | bool | `false` | Enable BBOT integration |
| integrations.bbot.image.pullPolicy | string | `"IfNotPresent"` | Image pull policy |
| integrations.bbot.image.repository | string | `"intelowlproject/intelowl_bbot_analyzer"` | BBOT image repository |
| integrations.bbot.image.tag | string | `""` | Image tag (defaults to app.version) |
| integrations.bbot.resources.limits.cpu | string | `"1"` | CPU limit |
| integrations.bbot.resources.limits.memory | string | `"2Gi"` | Memory limit |
| integrations.bbot.resources.requests.cpu | string | `"250m"` | CPU request |
| integrations.bbot.resources.requests.memory | string | `"512Mi"` | Memory request |
| integrations.bbot.service.port | int | `5001` | Service port |
| integrations.cyberchef.enabled | bool | `false` | Enable CyberChef integration |
| integrations.cyberchef.image.pullPolicy | string | `"IfNotPresent"` | Image pull policy |
| integrations.cyberchef.image.repository | string | `"intelowlproject/intelowl_cyberchef"` | CyberChef image repository |
| integrations.cyberchef.image.tag | string | `""` | CyberChef image tag (defaults to app.version) |
| integrations.cyberchef.resources.limits.cpu | string | `"500m"` | CPU limit |
| integrations.cyberchef.resources.limits.memory | string | `"512Mi"` | Memory limit |
| integrations.cyberchef.resources.requests.cpu | string | `"100m"` | CPU request |
| integrations.cyberchef.resources.requests.memory | string | `"256Mi"` | Memory request |
| integrations.cyberchef.service.port | int | `3000` | Service port |
| integrations.malwareTools.enabled | bool | `false` | Enable Malware Tools integration |
| integrations.malwareTools.image.pullPolicy | string | `"IfNotPresent"` | Image pull policy |
| integrations.malwareTools.image.repository | string | `"intelowlproject/intelowl_malware_tools_analyzers"` | Malware Tools image repository |
| integrations.malwareTools.image.tag | string | `""` | Image tag (defaults to app.version) |
| integrations.malwareTools.resources.limits.cpu | string | `"1"` | CPU limit |
| integrations.malwareTools.resources.limits.memory | string | `"2Gi"` | Memory limit |
| integrations.malwareTools.resources.requests.cpu | string | `"250m"` | CPU request |
| integrations.malwareTools.resources.requests.memory | string | `"512Mi"` | Memory request |
| integrations.malwareTools.service.port | int | `4002` | Service port |
| integrations.nuclei.enabled | bool | `false` | Enable Nuclei integration |
| integrations.nuclei.image.pullPolicy | string | `"IfNotPresent"` | Image pull policy |
| integrations.nuclei.image.repository | string | `"intelowlproject/intelowl_nuclei_analyzer"` | Nuclei image repository |
| integrations.nuclei.image.tag | string | `""` | Image tag (defaults to app.version) |
| integrations.nuclei.resources.limits.cpu | string | `"500m"` | CPU limit |
| integrations.nuclei.resources.limits.memory | string | `"1Gi"` | Memory limit |
| integrations.nuclei.resources.requests.cpu | string | `"100m"` | CPU request |
| integrations.nuclei.resources.requests.memory | string | `"256Mi"` | Memory request |
| integrations.nuclei.service.port | int | `4008` | Service port |
| integrations.pcapAnalyzers.enabled | bool | `false` | Enable PCAP Analyzers integration |
| integrations.pcapAnalyzers.image.pullPolicy | string | `"IfNotPresent"` | Image pull policy |
| integrations.pcapAnalyzers.image.repository | string | `"intelowlproject/intelowl_pcap_analyzers"` | PCAP Analyzers image repository |
| integrations.pcapAnalyzers.image.tag | string | `""` | Image tag (defaults to app.version) |
| integrations.pcapAnalyzers.resources.limits.cpu | string | `"1"` | CPU limit |
| integrations.pcapAnalyzers.resources.limits.memory | string | `"2Gi"` | Memory limit |
| integrations.pcapAnalyzers.resources.requests.cpu | string | `"250m"` | CPU request |
| integrations.pcapAnalyzers.resources.requests.memory | string | `"512Mi"` | Memory request |
| integrations.pcapAnalyzers.service.port | int | `4004` | Service port |
| integrations.phishingAnalyzers.enabled | bool | `false` | Enable Phishing Analyzers integration (includes Selenium) |
| integrations.phishingAnalyzers.image.pullPolicy | string | `"IfNotPresent"` | Image pull policy |
| integrations.phishingAnalyzers.image.repository | string | `"intelowlproject/intelowl_phishing_analyzers"` | Phishing Analyzers image repository |
| integrations.phishingAnalyzers.image.tag | string | `""` | Image tag (defaults to app.version) |
| integrations.phishingAnalyzers.resources.limits.cpu | string | `"1"` | CPU limit |
| integrations.phishingAnalyzers.resources.limits.memory | string | `"2Gi"` | Memory limit |
| integrations.phishingAnalyzers.resources.requests.cpu | string | `"250m"` | CPU request |
| integrations.phishingAnalyzers.resources.requests.memory | string | `"512Mi"` | Memory request |
| integrations.phishingAnalyzers.selenium.chromium.image.repository | string | `"selenium/node-chromium"` | Chromium node image repository |
| integrations.phishingAnalyzers.selenium.chromium.image.tag | string | `"145.0"` | Chromium node image tag |
| integrations.phishingAnalyzers.selenium.chromium.maxSessions | int | `4` | Maximum sessions per node |
| integrations.phishingAnalyzers.selenium.chromium.replicaCount | int | `1` | Number of Chromium nodes |
| integrations.phishingAnalyzers.selenium.chromium.resources.limits.cpu | string | `"1"` | CPU limit |
| integrations.phishingAnalyzers.selenium.chromium.resources.limits.memory | string | `"2Gi"` | Memory limit |
| integrations.phishingAnalyzers.selenium.chromium.resources.requests.cpu | string | `"500m"` | CPU request |
| integrations.phishingAnalyzers.selenium.chromium.resources.requests.memory | string | `"1Gi"` | Memory request |
| integrations.phishingAnalyzers.selenium.chromium.shmSize | string | `"2Gi"` | Shared memory size for Chromium |
| integrations.phishingAnalyzers.selenium.hub.image.repository | string | `"selenium/hub"` | Selenium Hub image repository |
| integrations.phishingAnalyzers.selenium.hub.image.tag | string | `"4.41"` | Selenium Hub image tag |
| integrations.phishingAnalyzers.selenium.hub.resources.limits.cpu | string | `"500m"` | CPU limit |
| integrations.phishingAnalyzers.selenium.hub.resources.limits.memory | string | `"1Gi"` | Memory limit |
| integrations.phishingAnalyzers.selenium.hub.resources.requests.cpu | string | `"100m"` | CPU request |
| integrations.phishingAnalyzers.selenium.hub.resources.requests.memory | string | `"256Mi"` | Memory request |
| integrations.phishingAnalyzers.service.port | int | `4005` | Service port |
| integrations.phoneinfoga.enabled | bool | `false` | Enable PhoneInfoga integration |
| integrations.phoneinfoga.image.pullPolicy | string | `"IfNotPresent"` | Image pull policy |
| integrations.phoneinfoga.image.repository | string | `"sundowndev/phoneinfoga"` | PhoneInfoga image repository |
| integrations.phoneinfoga.image.tag | string | `"v2.11.0"` | Image tag |
| integrations.phoneinfoga.resources.limits.cpu | string | `"500m"` | CPU limit |
| integrations.phoneinfoga.resources.limits.memory | string | `"512Mi"` | Memory limit |
| integrations.phoneinfoga.resources.requests.cpu | string | `"100m"` | CPU request |
| integrations.phoneinfoga.resources.requests.memory | string | `"128Mi"` | Memory request |
| integrations.phoneinfoga.service.port | int | `5000` | Service port |
| integrations.phunter.enabled | bool | `false` | Enable Phunter integration |
| integrations.phunter.image.pullPolicy | string | `"IfNotPresent"` | Image pull policy |
| integrations.phunter.image.repository | string | `"intelowlproject/phunter"` | Phunter image repository |
| integrations.phunter.image.tag | string | `""` | Image tag (defaults to app.version) |
| integrations.phunter.resources.limits.cpu | string | `"500m"` | CPU limit |
| integrations.phunter.resources.limits.memory | string | `"512Mi"` | Memory limit |
| integrations.phunter.resources.requests.cpu | string | `"100m"` | CPU request |
| integrations.phunter.resources.requests.memory | string | `"256Mi"` | Memory request |
| integrations.phunter.service.port | int | `5612` | Service port |
| integrations.thug.enabled | bool | `false` | Enable Thug integration |
| integrations.thug.image.pullPolicy | string | `"IfNotPresent"` | Image pull policy |
| integrations.thug.image.repository | string | `"intelowlproject/intelowl_thug"` | Thug image repository |
| integrations.thug.image.tag | string | `""` | Image tag (defaults to app.version) |
| integrations.thug.resources.limits.cpu | string | `"1"` | CPU limit |
| integrations.thug.resources.limits.memory | string | `"2Gi"` | Memory limit |
| integrations.thug.resources.requests.cpu | string | `"250m"` | CPU request |
| integrations.thug.resources.requests.memory | string | `"512Mi"` | Memory request |
| integrations.thug.service.port | int | `4002` | Service port |
| integrations.torAnalyzers.enabled | bool | `false` | Enable Tor Analyzers integration |
| integrations.torAnalyzers.image.pullPolicy | string | `"IfNotPresent"` | Image pull policy |
| integrations.torAnalyzers.image.repository | string | `"intelowlproject/intelowl_tor_analyzers"` | Tor Analyzers image repository |
| integrations.torAnalyzers.image.tag | string | `""` | Image tag (defaults to app.version) |
| integrations.torAnalyzers.resources.limits.cpu | string | `"500m"` | CPU limit |
| integrations.torAnalyzers.resources.limits.memory | string | `"1Gi"` | Memory limit |
| integrations.torAnalyzers.resources.requests.cpu | string | `"100m"` | CPU request |
| integrations.torAnalyzers.resources.requests.memory | string | `"256Mi"` | Memory request |
| integrations.torAnalyzers.service.port | int | `4001` | Service port |

### Networking parameters

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| networking.gateway.create | bool | `true` | Create Gateway resource |
| networking.gateway.gatewayClass.create | bool | `false` | Create GatewayClass (usually created by the provider) |
| networking.gateway.gatewayClass.name | string | `"nginx"` | GatewayClass name to use |
| networking.gateway.httpRoute.create | bool | `true` | Create HTTPRoute |
| networking.gateway.httpRoute.hostnames | list | `["intelowl.local"]` | Hostnames for the route |
| networking.gateway.httpRoute.websocket.enabled | bool | `true` | Enable WebSocket route for Daphne |
| networking.gateway.httpRoute.websocket.path | string | `"/ws"` | WebSocket path prefix |
| networking.gateway.listeners | list | `[{"allowedRoutes":{"namespaces":{"from":"Same"}},"name":"http","port":80,"protocol":"HTTP"}]` | Gateway listeners configuration |
| networking.gateway.name | string | `""` | Gateway name (auto-generated if empty) |
| networking.gatewayProvider | string | `"nginx-gateway-fabric"` | Gateway API provider: nginx-gateway-fabric, envoy-gateway, istio, kong, traefik |
| networking.ingress.annotations | object | `{}` | Ingress annotations |
| networking.ingress.className | string | `"nginx"` | Ingress class name |
| networking.ingress.enabled | bool | `false` | Enable Ingress |
| networking.ingress.hosts | list | `[{"host":"intelowl.local","paths":[{"path":"/","pathType":"Prefix"}]}]` | Ingress hosts configuration |
| networking.ingress.tls | list | `[]` | TLS configuration |
| networking.type | string | `"gateway"` | Networking type: "gateway" (Gateway API) or "ingress" (traditional Ingress) |

### Network Policy parameters

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| networkPolicy.allowExternalEgress | bool | `true` | Allow external egress (required for analyzers that need internet access) |
| networkPolicy.allowedNamespaces | list | `[]` | Allow traffic from specific namespaces |
| networkPolicy.enabled | bool | `false` | Enable network policies |

### RBAC parameters

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| rbac.annotations | object | `{}` | Annotations for ServiceAccount |
| rbac.create | bool | `true` | Create ServiceAccount |
| rbac.createRole | bool | `true` | Create Role and RoleBinding |
| rbac.serviceAccountName | string | `""` | ServiceAccount name (auto-generated if empty) |

### Security Context parameters

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| containerSecurityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"readOnlyRootFilesystem":false,"seccompProfile":{"type":"RuntimeDefault"}}` | Container security context applied to all containers |
| podSecurityContext | object | `{"fsGroup":33,"runAsGroup":33,"runAsNonRoot":true,"runAsUser":33}` | Pod security context applied to all pods |

### Migration parameters

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| migration.enabled | bool | `true` | Enable migration job as pre-install/pre-upgrade hook |
| migration.resources.limits.cpu | string | `"500m"` | CPU limit for migration job |
| migration.resources.limits.memory | string | `"1Gi"` | Memory limit for migration job |
| migration.resources.requests.cpu | string | `"250m"` | CPU request for migration job |
| migration.resources.requests.memory | string | `"512Mi"` | Memory request for migration job |
| migration.timeout | int | `600` | Migration timeout in seconds |

### External Secrets parameters

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| externalSecrets.enabled | bool | `false` | Enable External Secrets Operator integration |
| externalSecrets.refreshInterval | string | `"1h"` | Refresh interval for secrets |
| externalSecrets.remoteRefs.dbPassword.key | string | `"intelowl/secrets"` | Remote key for database password |
| externalSecrets.remoteRefs.dbPassword.property | string | `"DB_PASSWORD"` | Property name in remote secret |
| externalSecrets.remoteRefs.djangoSecret.key | string | `"intelowl/secrets"` | Remote key for Django secret |
| externalSecrets.remoteRefs.djangoSecret.property | string | `"DJANGO_SECRET"` | Property name in remote secret |
| externalSecrets.remoteRefs.redisPassword.key | string | `"intelowl/secrets"` | Remote key for Redis password |
| externalSecrets.remoteRefs.redisPassword.property | string | `"REDIS_PASSWORD"` | Property name in remote secret |
| externalSecrets.secretStoreRef.kind | string | `"ClusterSecretStore"` | SecretStore kind |
| externalSecrets.secretStoreRef.name | string | `"cluster-secret-store"` | SecretStore name |

### Metrics parameters

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| metrics.enabled | bool | `false` | Enable Prometheus metrics |
| metrics.podMonitor.enabled | bool | `false` | Enable PodMonitor for Prometheus Operator |
| metrics.podMonitor.interval | string | `"30s"` | Scrape interval |
| metrics.podMonitor.labels | object | `{}` | Additional labels for PodMonitor |
| metrics.podMonitor.scrapeTimeout | string | `"10s"` | Scrape timeout |
| metrics.serviceMonitor.enabled | bool | `false` | Enable ServiceMonitor for Prometheus Operator |
| metrics.serviceMonitor.interval | string | `"30s"` | Scrape interval |
| metrics.serviceMonitor.labels | object | `{}` | Additional labels for ServiceMonitor |
| metrics.serviceMonitor.scrapeTimeout | string | `"10s"` | Scrape timeout |

### Elasticsearch parameters (ECK)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| elasticsearch.affinity | object | `{}` | Affinity rules for Elasticsearch pods |
| elasticsearch.allowMmap | bool | `false` | Allow mmap (set to true for production performance) |
| elasticsearch.config | object | `{}` | Additional Elasticsearch configuration |
| elasticsearch.enabled | bool | `false` | Enable Elasticsearch for analysis results indexing |
| elasticsearch.kibana.enabled | bool | `true` | Enable Kibana dashboard |
| elasticsearch.kibana.ingress.annotations | object | `{}` | Ingress annotations |
| elasticsearch.kibana.ingress.className | string | `""` | Ingress class name |
| elasticsearch.kibana.ingress.enabled | bool | `false` | Enable Ingress for Kibana |
| elasticsearch.kibana.ingress.hosts | list | `[{"host":"kibana.intelowl.local","paths":[{"path":"/","pathType":"Prefix"}]}]` | Ingress hosts |
| elasticsearch.kibana.ingress.tls | list | `[]` | TLS configuration |
| elasticsearch.kibana.nodeSelector | object | `{}` | Node selector for Kibana pods |
| elasticsearch.kibana.replicas | int | `1` | Number of Kibana replicas |
| elasticsearch.kibana.resources.limits.cpu | string | `"500m"` | CPU limit for Kibana |
| elasticsearch.kibana.resources.limits.memory | string | `"1Gi"` | Memory limit for Kibana |
| elasticsearch.kibana.resources.requests.cpu | string | `"250m"` | CPU request for Kibana |
| elasticsearch.kibana.resources.requests.memory | string | `"512Mi"` | Memory request for Kibana |
| elasticsearch.kibana.tolerations | list | `[]` | Tolerations for Kibana pods |
| elasticsearch.nodeSelector | object | `{}` | Node selector for Elasticsearch pods |
| elasticsearch.operator.enabled | bool | `false` | Install ECK operator via this chart (set to false if ECK operator is already installed) |
| elasticsearch.replicas | int | `1` | Number of Elasticsearch nodes |
| elasticsearch.resources.limits.cpu | string | `"2"` | CPU limit for Elasticsearch |
| elasticsearch.resources.limits.memory | string | `"4Gi"` | Memory limit for Elasticsearch |
| elasticsearch.resources.requests.cpu | string | `"500m"` | CPU request for Elasticsearch |
| elasticsearch.resources.requests.memory | string | `"2Gi"` | Memory request for Elasticsearch |
| elasticsearch.storage.size | string | `"30Gi"` | Storage size for Elasticsearch data |
| elasticsearch.storage.storageClass | string | `""` | Storage class (uses global.storageClass if empty) |
| elasticsearch.tolerations | list | `[]` | Tolerations for Elasticsearch pods |
| elasticsearch.version | string | `"8.19.12"` | Elasticsearch version |

### Superuser parameters

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| superuser.email | string | `"admin@example.com"` | Superuser email |
| superuser.enabled | bool | `false` | Enable automatic superuser creation (post-install hook) |
| superuser.existingSecret | string | `""` | Use existing secret for superuser password (key: superuser-password) |
| superuser.password | string | `""` | Superuser password (auto-generated if empty) |
| superuser.username | string | `"admin"` | Superuser username |

### Celery Restart parameters

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| celeryRestart.enabled | bool | `false` | Enable weekly Celery worker restart CronJob |
| celeryRestart.schedule | string | `"0 3 * * 0"` | Cron schedule (default: every Sunday at 3:00 AM) |

### Log Cleanup parameters

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| logCleanup.enabled | bool | `false` | Enable log cleanup CronJob |
| logCleanup.retentionDays | int | `30` | Number of days to retain log files |
| logCleanup.schedule | string | `"0 2 * * *"` | Cron schedule (default: every day at 2:00 AM) |

### PostgreSQL parameters (CloudNative-PG)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| postgresql.affinity | object | `{}` | Affinity rules for PostgreSQL pods |
| postgresql.backup.destinationPath | string | `""` | S3 destination path |
| postgresql.backup.enabled | bool | `false` | Enable backup to S3-compatible storage |
| postgresql.backup.endpointURL | string | `""` | S3 endpoint URL |
| postgresql.backup.retentionPolicy | string | `"30d"` | Backup retention policy |
| postgresql.backup.s3Credentials.accessKeyIdKey | string | `"ACCESS_KEY_ID"` | Key for access key ID |
| postgresql.backup.s3Credentials.secretAccessKeyKey | string | `"ACCESS_SECRET_KEY"` | Key for secret access key |
| postgresql.backup.s3Credentials.secretName | string | `""` | Secret name containing S3 credentials |
| postgresql.database | string | `"intel_owl_db"` | Database name |
| postgresql.enabled | bool | `true` | Enable PostgreSQL (creates CNPG Cluster resource) |
| postgresql.existingSecret | string | `""` | Use existing secret for credentials |
| postgresql.image.pullPolicy | string | `"IfNotPresent"` | Image pull policy |
| postgresql.image.repository | string | `"ghcr.io/cloudnative-pg/postgresql"` | PostgreSQL image repository |
| postgresql.image.tag | string | `"16"` | PostgreSQL version tag |
| postgresql.initdb.postInitSQL | list | `[]` | Post-init SQL statements |
| postgresql.instances | int | `1` | Number of PostgreSQL instances (1 for dev, 3 for HA) |
| postgresql.monitoring.enabled | bool | `false` | Enable PostgreSQL monitoring |
| postgresql.monitoring.podMonitor | bool | `false` | Enable PodMonitor for PostgreSQL |
| postgresql.nodeSelector | object | `{}` | Node selector for PostgreSQL pods |
| postgresql.operator.enabled | bool | `false` | Install CloudNative-PG operator via this chart (set to true only if not already installed) |
| postgresql.parameters | object | `{}` | PostgreSQL server parameters |
| postgresql.password | string | `""` | Database password (auto-generated if empty) |
| postgresql.resources.limits.cpu | string | `"500m"` | CPU limit for PostgreSQL |
| postgresql.resources.limits.memory | string | `"1Gi"` | Memory limit for PostgreSQL |
| postgresql.resources.requests.cpu | string | `"100m"` | CPU request for PostgreSQL |
| postgresql.resources.requests.memory | string | `"256Mi"` | Memory request for PostgreSQL |
| postgresql.storage.size | string | `"10Gi"` | Storage size for PostgreSQL data |
| postgresql.storage.storageClass | string | `""` | Storage class (uses global.storageClass if empty) |
| postgresql.synchronous.enabled | bool | `false` | Enable synchronous replication (requires instances > 1) |
| postgresql.synchronous.maxSyncReplicas | int | `2` | Maximum synchronous replicas |
| postgresql.synchronous.minSyncReplicas | int | `1` | Minimum synchronous replicas |
| postgresql.tolerations | list | `[]` | Tolerations for PostgreSQL pods |
| postgresql.username | string | `"intelowl"` | Database username |
| postgresql.walStorage.enabled | bool | `false` | Enable separate WAL storage |
| postgresql.walStorage.size | string | `"2Gi"` | WAL storage size |
| postgresql.walStorage.storageClass | string | `""` | WAL storage class |

### Redis parameters (CloudPirates)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| redis.affinity | object | `{}` | Affinity rules for Redis pods |
| redis.architecture | string | `"standalone"` | Redis architecture: standalone or replication |
| redis.auth.enabled | bool | `true` | Enable Redis authentication |
| redis.auth.existingSecret | string | `""` | Use existing secret for password |
| redis.auth.existingSecretPasswordKey | string | `"redis-password"` | Key in existingSecret containing the password |
| redis.auth.password | string | `""` | Redis password (auto-generated if empty) |
| redis.enabled | bool | `true` | Enable Redis subchart |
| redis.nodeSelector | object | `{}` | Node selector for Redis pods |
| redis.persistence.enabled | bool | `true` | Enable Redis persistence |
| redis.persistence.size | string | `"5Gi"` | Persistence storage size |
| redis.persistence.storageClass | string | `""` | Storage class |
| redis.resources.limits.cpu | string | `"500m"` | CPU limit for Redis |
| redis.resources.limits.memory | string | `"512Mi"` | Memory limit for Redis |
| redis.resources.requests.cpu | string | `"100m"` | CPU request for Redis |
| redis.resources.requests.memory | string | `"128Mi"` | Memory request for Redis |
| redis.sentinel.enabled | bool | `false` | Enable Sentinel for HA (requires architecture: replication) |
| redis.sentinel.quorum | int | `2` | Sentinel quorum |
| redis.tolerations | list | `[]` | Tolerations for Redis pods |

### RabbitMQ parameters (CloudPirates)

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| rabbitmq.affinity | object | `{}` | Affinity rules for RabbitMQ pods |
| rabbitmq.auth.existingSecret | string | `""` | Use existing secret for credentials |
| rabbitmq.auth.existingSecretPasswordKey | string | `"password"` | Key in existingSecret containing the password (CloudPirates chart uses "password") |
| rabbitmq.auth.password | string | `""` | RabbitMQ password (auto-generated if empty) |
| rabbitmq.auth.username | string | `"intelowl"` | RabbitMQ username |
| rabbitmq.enabled | bool | `false` | Enable RabbitMQ subchart |
| rabbitmq.management.enabled | bool | `true` | Enable RabbitMQ management plugin |
| rabbitmq.nodeSelector | object | `{}` | Node selector for RabbitMQ pods |
| rabbitmq.persistence.enabled | bool | `true` | Enable RabbitMQ persistence |
| rabbitmq.persistence.size | string | `"5Gi"` | Persistence storage size |
| rabbitmq.persistence.storageClass | string | `""` | Storage class |
| rabbitmq.resources.limits.cpu | string | `"500m"` | CPU limit for RabbitMQ |
| rabbitmq.resources.limits.memory | string | `"1Gi"` | Memory limit for RabbitMQ |
| rabbitmq.resources.requests.cpu | string | `"100m"` | CPU request for RabbitMQ |
| rabbitmq.resources.requests.memory | string | `"256Mi"` | Memory request for RabbitMQ |
| rabbitmq.tolerations | list | `[]` | Tolerations for RabbitMQ pods |
| rabbitmq.vhost | string | `"/"` | RabbitMQ virtual host |

## Examples

Example value files are provided in the `examples/` directory:

| File                     | Description                                      |
| ------------------------ | ------------------------------------------------ |
| `minimal.yaml`           | Minimal deployment for testing                   |
| `development.yaml`       | Development environment with debug enabled       |
| `production.yaml`        | Production-ready HA configuration                |
| `with-ingress.yaml`      | Using traditional Ingress instead of Gateway API |
| `with-rabbitmq.yaml`     | Using RabbitMQ instead of Redis as broker        |
| `with-integrations.yaml` | Enabling optional analyzer integrations          |
| `with-elasticsearch.yaml`| Elasticsearch + Kibana for results indexing      |

## Testing

After installation, validate the deployment:

```bash
helm test intelowl -n intelowl
```

This runs connectivity tests for Nginx, uWSGI, PostgreSQL, and Redis.

## Maintenance

### Celery Worker Restart

Celery workers may accumulate memory over time. Enable the automatic restart CronJob:

```yaml
celeryRestart:
  enabled: true
  schedule: "0 3 * * 0"  # Every Sunday at 3:00 AM
```

### Log Cleanup

Enable automatic cleanup of old log files:

```yaml
logCleanup:
  enabled: true
  schedule: "0 2 * * *"  # Every day at 2:00 AM
  retentionDays: 30
```

### Notifications

Configure Slack and/or email notifications:

```yaml
app:
  slack:
    enabled: true
    token: "xoxb-your-token"
    defaultChannel: "#intelowl-alerts"
  email:
    enabled: true
    host: "smtp.example.com"
    port: 587
    hostUser: "alerts@example.com"
    hostPassword: "your-password"
    defaultFromEmail: "intelowl@example.com"
    useTls: true
```

## License

This Helm chart is licensed under the AGPL-3.0 license, consistent with IntelOwl.

## Links

- [IntelOwl Documentation](https://intelowl.readthedocs.io/)
- [IntelOwl GitHub](https://github.com/intelowlproject/IntelOwl)
- [Helm Documentation](https://helm.sh/docs/)
- [CloudNative-PG Documentation](https://cloudnative-pg.io/documentation/)
- [Gateway API Documentation](https://gateway-api.sigs.k8s.io/)
- [ECK Documentation](https://www.elastic.co/guide/en/cloud-on-k8s/current/k8s-overview.html)
