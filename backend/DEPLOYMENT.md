# Deployment Guide – AI-Powered Cloud Security Dashboard
## Step-by-Step Production Setup

---

## Prerequisites

| Tool       | Version  | Install |
|------------|----------|---------|
| Docker     | ≥ 24.0   | https://docs.docker.com/get-docker/ |
| Docker Compose | ≥ 2.20 | https://docs.docker.com/compose/ |
| kubectl    | ≥ 1.28   | https://kubernetes.io/docs/tasks/tools/ |
| Terraform  | ≥ 1.6    | https://developer.hashicorp.com/terraform/install |
| AWS CLI    | ≥ 2.0    | https://aws.amazon.com/cli/ |
| Node.js    | ≥ 20     | https://nodejs.org/ |
| Python     | ≥ 3.11   | https://python.org/ |

---

## Option A: Local Development (Docker Compose)

### Step 1 – Clone and configure

```bash
git clone https://github.com/your-org/cloud-security-dashboard.git
cd cloud-security-dashboard

# Copy and edit env vars
cp .env.example .env
```

### Step 2 – Start the full stack

```bash
# Build and start all services
docker-compose up -d

# Check all services are healthy
docker-compose ps

# Watch logs
docker-compose logs -f api
docker-compose logs -f ml-service
```

### Step 3 – Initialize the database

```bash
# Apply schema (auto-runs via docker-entrypoint)
docker exec sec-postgres psql -U admin -d security_db -f /docker-entrypoint-initdb.d/schema.sql

# Verify seed data
docker exec sec-postgres psql -U admin -d security_db -c "SELECT count(*) FROM alerts;"
```

### Step 4 – Train ML models

```bash
# Enter the ML container
docker exec -it sec-ml bash

# Generate dataset and train all models
python models.py --train

# Verify models saved
ls /models/
# Expected: isolation_forest.pkl  random_forest.pkl  lstm_model.keras
#           risk_scorer.keras  if_scaler.pkl  rf_scaler.pkl ...
```

### Step 5 – Create Kafka topics (auto-created by kafka-init service)

```bash
# Verify topics exist
docker exec sec-kafka kafka-topics --bootstrap-server localhost:9092 --list
```

### Step 6 – Start log generator (simulated traffic)

```bash
docker-compose up -d log-generator

# Watch events flowing through Kafka
docker exec sec-kafka kafka-console-consumer \
  --bootstrap-server localhost:9092 \
  --topic cloud-logs-aws \
  --from-beginning \
  --max-messages 5
```

### Step 7 – Access services

| Service         | URL                            | Credentials         |
|-----------------|--------------------------------|---------------------|
| Dashboard       | http://localhost:3000          | admin / demo123     |
| API             | http://localhost:4000          | JWT via /api/auth/login |
| API Health      | http://localhost:4000/health   | -                   |
| ML Service      | http://localhost:5001/health   | X-API-Key header    |
| Kibana          | http://localhost:5601          | elastic / changeme  |
| Kafka UI        | http://localhost:8082          | -                   |
| Prometheus      | http://localhost:9090          | -                   |
| Grafana         | http://localhost:3001          | admin / admin123    |
| AlertManager    | http://localhost:9093          | -                   |

---

## Option B: Production – AWS with Terraform + EKS

### Step 1 – Configure AWS credentials

```bash
aws configure
# Enter: Access Key ID, Secret Access Key, Region (us-east-1)
```

### Step 2 – Create S3 bucket for Terraform state

```bash
aws s3 mb s3://your-terraform-state-bucket --region us-east-1
aws s3api put-bucket-versioning \
  --bucket your-terraform-state-bucket \
  --versioning-configuration Status=Enabled
```

### Step 3 – Deploy infrastructure

```bash
cd infrastructure/terraform

# Edit variables
cp terraform.tfvars.example terraform.tfvars
vi terraform.tfvars

# Initialize
terraform init

# Preview changes
terraform plan -out=tfplan

# Apply (creates VPC, EKS, RDS, MSK, OpenSearch)
# Takes ~20 minutes
terraform apply tfplan
```

### Step 4 – Configure kubectl

```bash
aws eks update-kubeconfig \
  --name security-eks \
  --region us-east-1

# Verify connection
kubectl get nodes
```

### Step 5 – Build and push Docker images to ECR

```bash
# Get ECR login token
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin \
  YOUR_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com

# Create ECR repositories
for repo in security-api security-ml security-frontend; do
  aws ecr create-repository --repository-name $repo --region us-east-1
done

# Build images
docker build -t security-api      -f infrastructure/docker/Dockerfile.api      backend/api/
docker build -t security-ml       -f infrastructure/docker/Dockerfile.ml       backend/ml/
docker build -t security-frontend -f infrastructure/docker/Dockerfile.frontend  frontend/

# Tag and push
REGISTRY=YOUR_ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com
for img in security-api security-ml security-frontend; do
  docker tag  $img:latest $REGISTRY/$img:latest
  docker push $REGISTRY/$img:latest
done
```

### Step 6 – Deploy to Kubernetes

```bash
# Create namespace
kubectl create namespace security-dashboard

# Create secrets (use AWS Secrets Manager in production)
kubectl create secret generic security-secrets \
  --from-literal=JWT_SECRET=your-production-secret \
  --from-literal=PG_USER=admin \
  --from-literal=PG_PASS=your-db-password \
  --from-literal=ES_USER=admin \
  --from-literal=ES_PASS=your-es-password \
  --from-literal=ML_API_KEY=your-ml-key \
  -n security-dashboard

# Update image tags in manifest
sed -i "s|security-api:latest|$REGISTRY/security-api:latest|g" \
  infrastructure/kubernetes/security-dashboard.yaml

# Deploy all services
kubectl apply -f infrastructure/kubernetes/security-dashboard.yaml

# Watch rollout
kubectl rollout status deployment/api      -n security-dashboard
kubectl rollout status deployment/ml-service -n security-dashboard
kubectl rollout status deployment/frontend  -n security-dashboard
```

### Step 7 – Deploy monitoring

```bash
# Add Helm repos
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo add grafana              https://grafana.github.io/helm-charts
helm repo update

# Install Prometheus stack
helm install prometheus prometheus-community/kube-prometheus-stack \
  -n monitoring --create-namespace \
  -f monitoring/prometheus-values.yaml

# Apply custom alerting rules
kubectl apply -f monitoring/alerts.yml -n monitoring

# Get Grafana admin password
kubectl get secret prometheus-grafana \
  -n monitoring -o jsonpath="{.data.admin-password}" | base64 -d
```

### Step 8 – Set up Ingress with TLS

```bash
# Install nginx ingress controller
helm install ingress-nginx ingress-nginx/ingress-nginx \
  -n ingress-nginx --create-namespace

# Install cert-manager for TLS
helm install cert-manager jetstack/cert-manager \
  -n cert-manager --create-namespace \
  --set installCRDs=true

# Apply cluster issuer (edit email address first)
kubectl apply -f infrastructure/kubernetes/cluster-issuer.yaml

# Update domain in ingress and apply
sed -i "s|security.yourdomain.com|your-actual-domain.com|g" \
  infrastructure/kubernetes/security-dashboard.yaml
kubectl apply -f infrastructure/kubernetes/security-dashboard.yaml
```

---

## Option C: CI/CD via GitHub Actions

### Required GitHub Secrets

Go to: Settings → Secrets and Variables → Actions

```
AWS_ACCOUNT_ID         = 123456789012
AWS_ACCESS_KEY_ID      = AKIA...
AWS_SECRET_ACCESS_KEY  = ...
SNYK_TOKEN             = ...
SLACK_WEBHOOK_URL      = https://hooks.slack.com/...
```

### Trigger deployment

```bash
git add .
git commit -m "feat: initial deployment"
git push origin main

# GitHub Actions will automatically:
# 1. Run Snyk security scan
# 2. Run unit + integration tests
# 3. Build Docker images
# 4. Scan with Trivy
# 5. Deploy to staging
# 6. Run OWASP ZAP DAST scan
# 7. Deploy to production
```

---

## Security Scanning Reference

### Trivy – Container scanning

```bash
# Scan a built image
trivy image security-api:latest

# Scan with JSON output
trivy image --format json --output trivy-report.json security-api:latest

# Scan Kubernetes manifests
trivy config infrastructure/kubernetes/

# Scan Terraform IaC
trivy config infrastructure/terraform/
```

### Snyk – Dependency scanning

```bash
# Install Snyk CLI
npm install -g snyk
snyk auth

# Scan Node.js dependencies
cd backend/api && snyk test

# Scan Python dependencies
cd backend/ml && snyk test --file=requirements.txt

# Monitor continuously
snyk monitor
```

### OWASP ZAP – DAST scanning

```bash
# Pull ZAP Docker image
docker pull zaproxy/zap-stable

# Run baseline scan
docker run -t zaproxy/zap-stable zap-baseline.py \
  -t http://localhost:4000

# Run full scan (authenticated)
docker run -t zaproxy/zap-stable zap-full-scan.py \
  -t http://localhost:4000 \
  -z "-config replacer.full_list(0).description=auth \
      -config replacer.full_list(0).enabled=true \
      -config replacer.full_list(0).matchtype=REQ_HEADER \
      -config replacer.full_list(0).matchstr=Authorization \
      -config replacer.full_list(0).replacement=Bearer\ YOUR_TOKEN"
```

---

## Monitoring Setup

### Import Grafana Dashboards

1. Open Grafana at http://localhost:3001
2. Login: admin / admin123
3. Go to Dashboards → Import
4. Upload files from `monitoring/grafana/dashboards/`

### Key metrics to monitor

```promql
# Threat detection rate
rate(threats_detected_total[5m])

# ML model inference latency
histogram_quantile(0.95, rate(ml_inference_duration_seconds_bucket[5m]))

# Alert rate by severity
sum by(severity) (rate(alerts_created_total[1h]))

# Events processed per second
rate(kafka_events_processed_total[1m])

# API error rate
rate(http_requests_total{status=~"5.."}[5m]) /
rate(http_requests_total[5m])
```

---

## Troubleshooting

```bash
# Check all pod statuses
kubectl get pods -n security-dashboard

# View pod logs
kubectl logs -f deployment/api -n security-dashboard

# Describe failing pod
kubectl describe pod <pod-name> -n security-dashboard

# Check service connectivity
kubectl exec -it deployment/api -n security-dashboard -- \
  curl http://elasticsearch-service:9200/_cluster/health

# Restart a deployment
kubectl rollout restart deployment/api -n security-dashboard

# Scale up
kubectl scale deployment/api --replicas=5 -n security-dashboard
```
