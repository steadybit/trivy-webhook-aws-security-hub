# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build the binary (entrypoint is main.go at repo root)
go build -o trivy-webhook-aws-security-hub

# Run locally (listens on :8080, requires AWS credentials in env)
./trivy-webhook-aws-security-hub

# Format / vet
go fmt ./...
go vet ./...

# Run tests (HTTP-level, AWS Security Hub + STS faked via internal/testutil)
go test ./...
go test -race -coverprofile=coverage.out ./... && go tool cover -func=coverage.out

# Build the multi-arch container image (matches CI)
docker buildx build --platform linux/amd64,linux/arm64 .

# Render the Helm chart locally
helm template charts/trivy-webhook-aws-security-hub
```

CI runs `go test` via `.github/workflows/test.yml`, which gates the Docker build/push in `pre-release.yml` and `release.yml` via `needs: test`.

## Architecture

This is a single-process HTTP webhook receiver that translates trivy-operator CRD reports into AWS Security Hub findings. The full request flow lives in `main.go`; `tools/main.go` only holds two small helpers (`GetVulnScore`, `ParseEnvBool`).

**Request flow** (`ProcessTrivyWebhook` in `main.go`):
1. Trivy-operator POSTs a CRD object as JSON to `/trivy-webhook`.
2. The body is first decoded into a stub `webhook{Kind, APIVersion}` to dispatch on `kind`.
3. A second decode into the matching `v1alpha1.*Report` struct (from `github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1`) extracts the data.
4. A per-kind builder converts the report into `[]types.AwsSecurityFinding`.
5. `importFindingsToSecurityHub` chunks findings into batches of 100 (the BatchImportFindings limit) and calls AWS Security Hub.

**Supported report kinds** (each can be toggled via env var):
- `VulnerabilityReport` → `getVulnerabilityReportFindings` — fully implemented; emits one finding per CVE with `Resource.Type=Container`.
- `ConfigAuditReport` → `getConfigAuditReportFindings` — fully implemented; emits one finding per failed check with `Resource.Type=Other`.
- `InfraAssessmentReport` → `getInfraAssessmentReport` — **stub**: only logs the report, returns no findings.
- `ClusterComplianceReport` → `getClusterComplianceReport` — **stub**: only logs the report, returns no findings.

When extending the stubs, mirror the structure of `getVulnerabilityReportFindings`: load AWS config, resolve account via `sts.GetCallerIdentity`, build the `ProductArn` as `arn:aws:securityhub:<region>::product/aquasecurity/aquasecurity`, and remember Security Hub's hard limits — `Description` must be ≤ 1024 chars (existing code truncates with `"..."`), `Id` must be unique per finding across re-imports, and severity `"UNKNOWN"` must be remapped to `"INFORMATIONAL"` (Security Hub does not accept `UNKNOWN`).

**AWS auth**: Uses the default AWS SDK credential chain (`config.LoadDefaultConfig`). In-cluster the chart expects IRSA — the user attaches a role via `serviceAccount.annotations`. Region comes from `AWS_REGION` (set in the chart's `config` block).

**Product subscription**: The `ProductArn` points to Aqua Security's product entry in Security Hub. The receiving AWS account must accept the "Aqua Security: Aqua Security" product subscription in Security Hub for `BatchImportFindings` to succeed — this is the most common cause of silent failures in production.

## Module path note

`go.mod` declares `module github.com/csepulveda/trivy-webhook-aws-security-hub` (the upstream fork). Internal imports (e.g. `tools`) use this path — do not rename the module without updating those imports.

## References

External specs and docs that govern the request and finding shapes — useful when extending the converters or debugging Security Hub rejections.

**Trivy-operator (input side)**
- Webhook integration / `OPERATOR_WEBHOOK_BROADCAST_URL`: https://aquasecurity.github.io/trivy-operator/latest/tutorials/integrations/webhook/
- `VulnerabilityReport` CRD: https://aquasecurity.github.io/trivy-operator/latest/docs/crds/vulnerability-report/
- `ConfigAuditReport` CRD: https://aquasecurity.github.io/trivy-operator/latest/docs/crds/configaudit-report/
- `InfraAssessmentReport` CRD: https://aquasecurity.github.io/trivy-operator/latest/docs/crds/infraassessment-report/
- `ClusterComplianceReport` CRD: https://aquasecurity.github.io/trivy-operator/latest/docs/crds/clustercompliance-report/
- Generated Go types (the structs we unmarshal into): https://pkg.go.dev/github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1

**AWS (output side)**
- Security Hub `BatchImportFindings`: https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_BatchImportFindings.html (100-finding batch limit, `Description` ≤ 1024 chars, allowed severity labels)
- AWS Security Finding Format (ASFF): https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html
- ASFF `Resources` object reference: https://docs.aws.amazon.com/securityhub/latest/userguide/asff-resources.html
- STS `GetCallerIdentity`: https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html
