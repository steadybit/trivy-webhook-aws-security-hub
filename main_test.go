package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"

	"github.com/csepulveda/trivy-webhook-aws-security-hub/internal/testutil"
)

const (
	testAccount = "123456789012"
	testRegion  = "us-east-1"
)

var testProductArn = "arn:aws:securityhub:" + testRegion + "::product/aquasecurity/aquasecurity"

var fixedNow = time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)

func defaultCfg() Config {
	return Config{
		InfraAssessmentEnable:   true,
		ConfigAuditEnable:       true,
		ClusterComplianceEnable: true,
		VulnerabilityEnable:     true,
	}
}

func newTestServer(t *testing.T, cfg Config) (*Server, *testutil.FakeAWS) {
	t.Helper()
	fake := testutil.NewFakeAWS(t)
	srv, err := NewServer(context.Background(), fake.Config(), cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv.now = func() time.Time { return fixedNow }
	return srv, fake
}

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

func postWebhook(t *testing.T, srv *Server, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/trivy-webhook", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rr, req)
	return rr
}

func postFixture(t *testing.T, srv *Server, name string) *httptest.ResponseRecorder {
	t.Helper()
	return postWebhook(t, srv, loadFixture(t, name))
}

func allFindings(imports []securityhub.BatchImportFindingsInput) []types.AwsSecurityFinding {
	var all []types.AwsSecurityFinding
	for _, in := range imports {
		all = append(all, in.Findings...)
	}
	return all
}

// vulnReportJSON builds a VulnerabilityReport payload with N synthetic vulnerabilities.
// Used for the batching and zero-findings paths where committing huge fixtures is wasteful.
func vulnReportJSON(t *testing.T, n int, mutate func(int, map[string]any)) []byte {
	t.Helper()
	vulns := make([]map[string]any, n)
	for i := 0; i < n; i++ {
		v := map[string]any{
			"vulnerabilityID":  fmt.Sprintf("CVE-2024-%05d", i),
			"resource":         "lib",
			"installedVersion": "1.0",
			"fixedVersion":     "1.1",
			"publishedDate":    "",
			"lastModifiedDate": "",
			"severity":         "HIGH",
			"title":            "synthetic",
			"description":      "synthetic description",
			"primaryLink":      "https://example.com/CVE",
			"links":            []string{},
		}
		if mutate != nil {
			mutate(i, v)
		}
		vulns[i] = v
	}
	body := map[string]any{
		"apiVersion": "aquasecurity.github.io/v1alpha1",
		"kind":       "VulnerabilityReport",
		"metadata": map[string]any{
			"name":      "synthetic",
			"namespace": "default",
			"labels":    map[string]string{"trivy-operator.container.name": "x"},
		},
		"report": map[string]any{
			"updateTimestamp": "2026-04-30T10:00:00Z",
			"scanner":         map[string]any{"name": "Trivy", "vendor": "Aqua Security", "version": "0.50.0"},
			"registry":        map[string]any{"server": "docker.io"},
			"artifact":        map[string]any{"repository": "library/x", "digest": "sha256:abc"},
			"summary":         map[string]any{"criticalCount": 0, "highCount": n, "mediumCount": 0, "lowCount": 0, "unknownCount": 0, "noneCount": 0},
			"vulnerabilities": vulns,
		},
	}
	out, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal synthetic report: %v", err)
	}
	return out
}

// ---- healthz ----

func TestHealthz_GET(t *testing.T) {
	srv, _ := newTestServer(t, defaultCfg())
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	if got := rr.Body.String(); got != "OK" {
		t.Errorf("body = %q, want %q", got, "OK")
	}
}

func TestHealthz_POST_returns405(t *testing.T) {
	srv, _ := newTestServer(t, defaultCfg())
	req := httptest.NewRequest(http.MethodPost, "/healthz", nil)
	rr := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", rr.Code)
	}
}

// ---- input validation ----

func TestWebhook_EmptyBody(t *testing.T) {
	srv, fake := newTestServer(t, defaultCfg())
	rr := postWebhook(t, srv, nil)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Empty request body") {
		t.Errorf("body = %q, want to contain Empty request body", rr.Body.String())
	}
	if n := len(fake.BatchImports()); n != 0 {
		t.Errorf("BatchImports calls = %d, want 0", n)
	}
}

func TestWebhook_MalformedJSON(t *testing.T) {
	srv, fake := newTestServer(t, defaultCfg())
	rr := postWebhook(t, srv, []byte("{not-json"))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Invalid JSON") {
		t.Errorf("body = %q, want to contain Invalid JSON", rr.Body.String())
	}
	if n := len(fake.BatchImports()); n != 0 {
		t.Errorf("BatchImports calls = %d, want 0", n)
	}
}

func TestWebhook_UnknownKind(t *testing.T) {
	srv, fake := newTestServer(t, defaultCfg())
	rr := postWebhook(t, srv, []byte(`{"kind":"WeirdKind","apiVersion":"v1"}`))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "unknown report type") {
		t.Errorf("body = %q, want to contain unknown report type", rr.Body.String())
	}
	if n := len(fake.BatchImports()); n != 0 {
		t.Errorf("BatchImports calls = %d, want 0", n)
	}
}

func TestWebhook_BodyReadFailure(t *testing.T) {
	srv, _ := newTestServer(t, defaultCfg())
	req := httptest.NewRequest(http.MethodPost, "/trivy-webhook", iotest.ErrReader(errors.New("boom")))
	rr := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Error reading request body") {
		t.Errorf("body = %q", rr.Body.String())
	}
}

// ---- VulnerabilityReport happy paths ----

func TestVulnReport_BasicDigest(t *testing.T) {
	srv, fake := newTestServer(t, defaultCfg())
	rr := postFixture(t, srv, "vulnerability_report_basic.json")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body=%q", rr.Code, rr.Body.String())
	}

	imports := fake.BatchImports()
	if len(imports) != 1 {
		t.Fatalf("BatchImports calls = %d, want 1", len(imports))
	}
	findings := imports[0].Findings
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(findings))
	}

	wantID := "index.docker.io/library/nginx@sha256:b6a85c1bb1f1f8f9b2c5d8e3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3-CVE-2021-23017"
	f := findings[0]
	if got := aws.ToString(f.Id); got != wantID {
		t.Errorf("Id = %q, want %q", got, wantID)
	}
	if got := aws.ToString(f.ProductArn); got != testProductArn {
		t.Errorf("ProductArn = %q, want %q", got, testProductArn)
	}
	if got := aws.ToString(f.AwsAccountId); got != testAccount {
		t.Errorf("AwsAccountId = %q, want %q", got, testAccount)
	}
	if f.RecordState != types.RecordStateActive {
		t.Errorf("RecordState = %v, want ACTIVE", f.RecordState)
	}
	if len(f.Resources) != 1 || aws.ToString(f.Resources[0].Type) != "Container" {
		t.Errorf("Resources = %+v, want one Container resource", f.Resources)
	}
	if got := aws.ToString(f.Resources[0].Id); got != "index.docker.io/library/nginx" {
		t.Errorf("Resource.Id = %q, want index.docker.io/library/nginx", got)
	}
	if got := aws.ToString(f.Resources[0].Region); got != testRegion {
		t.Errorf("Resource.Region = %q, want %q", got, testRegion)
	}
	if got := f.Resources[0].Details.Other["NvdCvssScoreV3"]; got != "9.800000" {
		t.Errorf("NvdCvssScoreV3 = %q, want 9.800000", got)
	}
	if got := aws.ToString(f.CreatedAt); got != fixedNow.Format(time.RFC3339) {
		t.Errorf("CreatedAt = %q, want %q", got, fixedNow.Format(time.RFC3339))
	}
}

func TestVulnReport_TagOnly_UsesTagInId(t *testing.T) {
	srv, fake := newTestServer(t, defaultCfg())
	rr := postFixture(t, srv, "vulnerability_report_tag_only.json")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", rr.Code, rr.Body.String())
	}
	findings := allFindings(fake.BatchImports())
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	wantID := "quay.io/redis/redis:7.0.5-CVE-2023-25155"
	if got := aws.ToString(findings[0].Id); got != wantID {
		t.Errorf("Id = %q, want %q", got, wantID)
	}
}

func TestVulnReport_UnknownSeverityRemapsToInformational(t *testing.T) {
	srv, fake := newTestServer(t, defaultCfg())
	rr := postFixture(t, srv, "vulnerability_report_unknown_severity.json")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", rr.Code, rr.Body.String())
	}
	findings := allFindings(fake.BatchImports())
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if got := string(findings[0].Severity.Label); got != "INFORMATIONAL" {
		t.Errorf("Severity.Label = %q, want INFORMATIONAL", got)
	}
}

func TestVulnReport_LongDescriptionTruncatedTo1024(t *testing.T) {
	longDesc := strings.Repeat("X", 1500)
	body := vulnReportJSON(t, 1, func(_ int, v map[string]any) {
		v["description"] = longDesc
	})

	srv, fake := newTestServer(t, defaultCfg())
	rr := postWebhook(t, srv, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", rr.Code, rr.Body.String())
	}
	findings := allFindings(fake.BatchImports())
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	got := aws.ToString(findings[0].Description)
	if len(got) != 1024 {
		t.Errorf("Description length = %d, want 1024", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Errorf("Description should end with ..., got suffix %q", got[max(0, len(got)-10):])
	}
}

func TestVulnReport_EmptyDescriptionFallsBackToTitle(t *testing.T) {
	srv, fake := newTestServer(t, defaultCfg())
	rr := postFixture(t, srv, "vulnerability_report_empty_description.json")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", rr.Code, rr.Body.String())
	}
	findings := allFindings(fake.BatchImports())
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	wantTitle := "Title used as fallback when description is empty"
	if got := aws.ToString(findings[0].Description); got != wantTitle {
		t.Errorf("Description = %q, want %q", got, wantTitle)
	}
}

func TestVulnReport_NilScoreRendersAsZero(t *testing.T) {
	srv, fake := newTestServer(t, defaultCfg())
	postFixture(t, srv, "vulnerability_report_empty_description.json")
	findings := allFindings(fake.BatchImports())
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if got := findings[0].Resources[0].Details.Other["NvdCvssScoreV3"]; got != "0.000000" {
		t.Errorf("NvdCvssScoreV3 = %q, want 0.000000", got)
	}
}

func TestVulnReport_BatchesAt100(t *testing.T) {
	body := vulnReportJSON(t, 250, nil)

	srv, fake := newTestServer(t, defaultCfg())
	rr := postWebhook(t, srv, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", rr.Code, rr.Body.String())
	}

	imports := fake.BatchImports()
	if len(imports) != 3 {
		t.Fatalf("BatchImports calls = %d, want 3", len(imports))
	}
	wantSizes := []int{100, 100, 50}
	for i, sz := range wantSizes {
		if got := len(imports[i].Findings); got != sz {
			t.Errorf("batch[%d] size = %d, want %d", i, got, sz)
		}
	}
}

func TestVulnReport_ZeroVulns_NoBatchCall(t *testing.T) {
	body := vulnReportJSON(t, 0, nil)

	srv, fake := newTestServer(t, defaultCfg())
	rr := postWebhook(t, srv, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", rr.Code, rr.Body.String())
	}
	if n := len(fake.BatchImports()); n != 0 {
		t.Errorf("BatchImports calls = %d, want 0", n)
	}
}

// ---- ConfigAuditReport ----

func TestConfigAudit_Basic(t *testing.T) {
	srv, fake := newTestServer(t, defaultCfg())
	rr := postFixture(t, srv, "config_audit_report_basic.json")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", rr.Code, rr.Body.String())
	}
	findings := allFindings(fake.BatchImports())
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(findings))
	}

	f := findings[0]
	if got := aws.ToString(f.Id); got != "KSV001-ReplicaSet/nginx-6d4cf56db6" {
		t.Errorf("Id = %q", got)
	}
	if len(f.Resources) != 1 || aws.ToString(f.Resources[0].Type) != "Other" {
		t.Errorf("Resources = %+v, want one Other resource", f.Resources)
	}
	if got := aws.ToString(f.Resources[0].Id); got != "ReplicaSet/nginx-6d4cf56db6" {
		t.Errorf("Resource.Id = %q", got)
	}
	wantMessage := "Container 'nginx' of ReplicaSet 'nginx-6d4cf56db6' should set 'securityContext.allowPrivilegeEscalation' to false"
	if got := f.Resources[0].Details.Other["Message"]; got != wantMessage {
		t.Errorf("Message = %q, want %q", got, wantMessage)
	}
}

func TestConfigAudit_UnknownSeverityRemaps(t *testing.T) {
	srv, fake := newTestServer(t, defaultCfg())
	rr := postFixture(t, srv, "config_audit_report_unknown_severity.json")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", rr.Code, rr.Body.String())
	}
	findings := allFindings(fake.BatchImports())
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if got := string(findings[0].Severity.Label); got != "INFORMATIONAL" {
		t.Errorf("Severity.Label = %q, want INFORMATIONAL", got)
	}
}

func TestConfigAudit_NoOwnerNoLabels_Returns400(t *testing.T) {
	srv, fake := newTestServer(t, defaultCfg())
	rr := postFixture(t, srv, "config_audit_report_no_owner.json")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body=%q", rr.Code, rr.Body.String())
	}
	if n := len(fake.BatchImports()); n != 0 {
		t.Errorf("BatchImports calls = %d, want 0", n)
	}
}

func TestConfigAudit_NoOwnerWithLabels_UsesLabels(t *testing.T) {
	srv, fake := newTestServer(t, defaultCfg())
	rr := postFixture(t, srv, "config_audit_report_no_owner_with_labels.json")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", rr.Code, rr.Body.String())
	}
	findings := allFindings(fake.BatchImports())
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if got := aws.ToString(findings[0].Resources[0].Id); got != "ReplicaSet/nginx-6d4cf56db6" {
		t.Errorf("Resource.Id = %q, want ReplicaSet/nginx-6d4cf56db6", got)
	}
	if got := aws.ToString(findings[0].Id); got != "KSV001-ReplicaSet/nginx-6d4cf56db6" {
		t.Errorf("Id = %q", got)
	}
}

func TestConfigAudit_EmptyMessages_EmitsFindingWithoutMessage(t *testing.T) {
	srv, fake := newTestServer(t, defaultCfg())
	rr := postFixture(t, srv, "config_audit_report_no_messages.json")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", rr.Code, rr.Body.String())
	}
	findings := allFindings(fake.BatchImports())
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	if _, present := findings[0].Resources[0].Details.Other["Message"]; present {
		t.Errorf("Message key should be absent when check has no messages, got %+v", findings[0].Resources[0].Details.Other)
	}
}

func TestConfigAudit_MultipleMessages_JoinsMessages(t *testing.T) {
	srv, fake := newTestServer(t, defaultCfg())
	rr := postFixture(t, srv, "config_audit_report_multi_messages.json")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", rr.Code, rr.Body.String())
	}
	findings := allFindings(fake.BatchImports())
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	want := "Container 'app' should set 'readOnlyRootFilesystem' to true\nContainer 'sidecar' should set 'readOnlyRootFilesystem' to true"
	if got := findings[0].Resources[0].Details.Other["Message"]; got != want {
		t.Errorf("Message = %q, want %q", got, want)
	}
}

// ---- Stubs ----

func TestInfraAssessment_NoFindings(t *testing.T) {
	srv, fake := newTestServer(t, defaultCfg())
	rr := postFixture(t, srv, "infra_assessment_report.json")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", rr.Code, rr.Body.String())
	}
	if n := len(fake.BatchImports()); n != 0 {
		t.Errorf("BatchImports calls = %d, want 0 (stub builder)", n)
	}
}

func TestClusterCompliance_NoFindings(t *testing.T) {
	srv, fake := newTestServer(t, defaultCfg())
	rr := postFixture(t, srv, "cluster_compliance_report.json")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", rr.Code, rr.Body.String())
	}
	if n := len(fake.BatchImports()); n != 0 {
		t.Errorf("BatchImports calls = %d, want 0 (stub builder)", n)
	}
}

// ---- Feature-flag toggles ----

func TestToggle_DisabledKindSkipsAWS(t *testing.T) {
	cases := []struct {
		name    string
		fixture string
		disable func(*Config)
	}{
		{"vulnerability", "vulnerability_report_basic.json", func(c *Config) { c.VulnerabilityEnable = false }},
		{"config audit", "config_audit_report_basic.json", func(c *Config) { c.ConfigAuditEnable = false }},
		{"infra assessment", "infra_assessment_report.json", func(c *Config) { c.InfraAssessmentEnable = false }},
		{"cluster compliance", "cluster_compliance_report.json", func(c *Config) { c.ClusterComplianceEnable = false }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := defaultCfg()
			tc.disable(&cfg)
			srv, fake := newTestServer(t, cfg)
			rr := postFixture(t, srv, tc.fixture)
			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, body=%q", rr.Code, rr.Body.String())
			}
			if n := len(fake.BatchImports()); n != 0 {
				t.Errorf("BatchImports calls = %d, want 0 when toggle disabled", n)
			}
		})
	}
}

// ---- AWS error propagation ----

func TestSecurityHub_5xxError_Propagates500(t *testing.T) {
	srv, fake := newTestServer(t, defaultCfg())
	fake.SecurityHubErrorOnCall = 1
	fake.SecurityHubError = &testutil.AWSError{
		StatusCode: http.StatusInternalServerError,
		Type:       "InternalServerError",
		Message:    "service unavailable",
	}
	rr := postFixture(t, srv, "vulnerability_report_basic.json")
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Error importing findings to Security Hub") {
		t.Errorf("body = %q", rr.Body.String())
	}
	if n := len(fake.BatchImports()); n < 1 {
		t.Errorf("BatchImports calls = %d, want >= 1 (SDK retries 5xx)", n)
	}
}

func TestSecurityHub_InvalidInput_PropagatesAs500(t *testing.T) {
	srv, fake := newTestServer(t, defaultCfg())
	fake.SecurityHubErrorOnCall = 1
	fake.SecurityHubError = &testutil.AWSError{
		StatusCode: http.StatusBadRequest,
		Type:       "InvalidInputException",
		Message:    "bad input",
	}
	rr := postFixture(t, srv, "vulnerability_report_basic.json")
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rr.Code)
	}
}

func TestSecurityHub_SecondBatchFails_FirstAlreadyImported(t *testing.T) {
	body := vulnReportJSON(t, 150, nil)

	srv, fake := newTestServer(t, defaultCfg())
	fake.SecurityHubErrorOnCall = 2
	fake.SecurityHubError = &testutil.AWSError{
		StatusCode: http.StatusInternalServerError,
		Type:       "InternalServerError",
		Message:    "second batch fails",
	}
	rr := postWebhook(t, srv, body)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rr.Code)
	}
	imports := fake.BatchImports()
	if len(imports) < 2 {
		t.Fatalf("BatchImports calls = %d, want >= 2 (first succeeded, second failed; SDK retries)", len(imports))
	}
	if len(imports[0].Findings) != 100 {
		t.Errorf("first batch size = %d, want 100", len(imports[0].Findings))
	}
	for i := 1; i < len(imports); i++ {
		if len(imports[i].Findings) != 50 {
			t.Errorf("batch[%d] size = %d, want 50 (second batch retries with same payload)", i, len(imports[i].Findings))
		}
	}
}

// ---- WebhookMsg envelope (OPERATOR_SEND_DELETED_REPORTS=true) ----

func envelope(t *testing.T, verb string, operatorObject []byte) []byte {
	t.Helper()
	out, err := json.Marshal(struct {
		Verb           string          `json:"verb"`
		OperatorObject json.RawMessage `json:"operatorObject"`
	}{Verb: verb, OperatorObject: operatorObject})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return out
}

func findingIDs(findings []types.AwsSecurityFinding) []string {
	ids := make([]string, len(findings))
	for i, f := range findings {
		ids[i] = aws.ToString(f.Id)
	}
	return ids
}

func runFixture(t *testing.T, body []byte) []types.AwsSecurityFinding {
	t.Helper()
	srv, fake := newTestServer(t, defaultCfg())
	rr := postWebhook(t, srv, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", rr.Code, rr.Body.String())
	}
	return allFindings(fake.BatchImports())
}

func TestProcessTrivyWebhook_DeleteEnvelope_VulnerabilityReport(t *testing.T) {
	raw := loadFixture(t, "vulnerability_report_basic.json")
	unwrapped := runFixture(t, raw)
	deleted := runFixture(t, envelope(t, "delete", raw))

	if got, want := findingIDs(deleted), findingIDs(unwrapped); !slices.Equal(got, want) {
		t.Errorf("delete-envelope Ids = %v, want %v (must match unwrapped path)", got, want)
	}
	for i, f := range deleted {
		if f.RecordState != types.RecordStateArchived {
			t.Errorf("RecordState[%d] = %v, want ARCHIVED", i, f.RecordState)
		}
	}
}

func TestProcessTrivyWebhook_DeleteEnvelope_ConfigAuditReport(t *testing.T) {
	raw := loadFixture(t, "config_audit_report_basic.json")
	unwrapped := runFixture(t, raw)
	deleted := runFixture(t, envelope(t, "delete", raw))

	if got, want := findingIDs(deleted), findingIDs(unwrapped); !slices.Equal(got, want) {
		t.Errorf("delete-envelope Ids = %v, want %v (must match unwrapped path)", got, want)
	}
	for i, f := range deleted {
		if f.RecordState != types.RecordStateArchived {
			t.Errorf("RecordState[%d] = %v, want ARCHIVED", i, f.RecordState)
		}
	}
}

func TestProcessTrivyWebhook_UpdateEnvelope(t *testing.T) {
	raw := loadFixture(t, "vulnerability_report_basic.json")
	unwrapped := runFixture(t, raw)
	updated := runFixture(t, envelope(t, "update", raw))

	if got, want := findingIDs(updated), findingIDs(unwrapped); !slices.Equal(got, want) {
		t.Errorf("update-envelope Ids = %v, want %v", got, want)
	}
	for i, f := range updated {
		if f.RecordState != types.RecordStateActive {
			t.Errorf("RecordState[%d] = %v, want ACTIVE", i, f.RecordState)
		}
	}
}

func TestProcessTrivyWebhook_UnwrappedStillWorks(t *testing.T) {
	findings := runFixture(t, loadFixture(t, "vulnerability_report_basic.json"))
	if len(findings) == 0 {
		t.Fatal("expected findings from unwrapped report")
	}
	for i, f := range findings {
		if f.RecordState != types.RecordStateActive {
			t.Errorf("RecordState[%d] = %v, want ACTIVE (regression: unwrapped path must still import)", i, f.RecordState)
		}
	}
}

func TestProcessTrivyWebhook_UnknownVerb(t *testing.T) {
	srv, fake := newTestServer(t, defaultCfg())
	rr := postWebhook(t, srv, envelope(t, "weird", loadFixture(t, "vulnerability_report_basic.json")))
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	if n := len(fake.BatchImports()); n != 0 {
		t.Errorf("BatchImports calls = %d, want 0 (unknown verb must not import)", n)
	}
}

func TestNewServer_STSFailureReturnsError(t *testing.T) {
	fake := testutil.NewFakeAWS(t)
	fake.STSError = &testutil.AWSError{
		StatusCode: http.StatusForbidden,
		Type:       "AccessDenied",
		Message:    "denied",
	}
	_, err := NewServer(context.Background(), fake.Config(), defaultCfg())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "failed to get caller identity") {
		t.Errorf("error = %v, want it to mention caller identity", err)
	}
}
