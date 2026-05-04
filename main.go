package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/csepulveda/trivy-webhook-aws-security-hub/internal/ignore"
	"github.com/csepulveda/trivy-webhook-aws-security-hub/tools"
	"github.com/gorilla/mux"
)

// trivyIgnoreRuleIDKey is the ProductFields marker that identifies findings
// suppressed by the trivy-ignore feature. The reconciler uses it to scope
// un-suppression to findings *we* suppressed, leaving operator-driven
// console suppressions untouched.
const trivyIgnoreRuleIDKey = "TrivyIgnoreRuleId"

type webhook struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"apiVersion"`
}

// webhookMsg is the envelope trivy-operator sends when
// OPERATOR_SEND_DELETED_REPORTS=true. Verb is "update" for create/update
// events and "delete" when the underlying CRD is removed. Without the
// envelope, raw report bodies are POSTed instead.
type webhookMsg struct {
	Verb           string          `json:"verb"`
	OperatorObject json.RawMessage `json:"operatorObject"`
}

const (
	verbUpdate = "update"
	verbDelete = "delete"
)

// Config holds feature flags
type Config struct {
	InfraAssessmentEnable   bool
	ConfigAuditEnable       bool
	ClusterComplianceEnable bool
	VulnerabilityEnable     bool
	IgnoreFile              string
	ReconcileInterval       time.Duration
}

func LoadConfig() Config {
	return Config{
		InfraAssessmentEnable:   tools.ParseEnvBool("INFRA_ASSESSMENT_ENABLE", true),
		ConfigAuditEnable:       tools.ParseEnvBool("CONFIG_AUDIT_ENABLE", true),
		ClusterComplianceEnable: tools.ParseEnvBool("CLUSTER_COMPLIANCE_ENABLE", true),
		VulnerabilityEnable:     tools.ParseEnvBool("VULNERABILITY_ENABLE", true),
		IgnoreFile:              os.Getenv("TRIVY_IGNORE_FILE"),
		ReconcileInterval:       tools.ParseEnvDuration("IGNORE_RECONCILE_INTERVAL", 24*time.Hour),
	}
}

func PrintConfig(cfg Config) {
	log.Printf("Loaded Configuration: %+v", cfg)
}

// Security Hub rejects "UNKNOWN" as a severity label; map to "INFORMATIONAL".
func remapSeverity(severity v1alpha1.Severity) string {
	if severity == "UNKNOWN" {
		return "INFORMATIONAL"
	}
	return string(severity)
}

// Security Hub caps Description at 1024 chars.
func truncateDescription(description string) string {
	if len(description) > 1024 {
		return description[:1021] + "..."
	}
	return description
}

var trivyProductFields = map[string]string{"Product Name": "Trivy"}

// errInvalidReport signals that the incoming report cannot be processed because
// of missing identifying data. The dispatcher maps this to HTTP 400.
var errInvalidReport = errors.New("invalid report")

// resolveConfigAuditTarget builds the "<Kind>/<Name>" identifier used as both
// the finding's Resource.Id and a component of its finding Id. Trivy-operator
// normally populates ownerReferences, but for orphaned or cluster-scoped
// reports we fall back to the resource labels it always sets.
func resolveConfigAuditTarget(report *v1alpha1.ConfigAuditReport) (string, error) {
	if len(report.OwnerReferences) > 0 {
		return fmt.Sprintf("%s/%s", report.OwnerReferences[0].Kind, report.OwnerReferences[0].Name), nil
	}
	kind := report.Labels["trivy-operator.resource.kind"]
	name := report.Labels["trivy-operator.resource.name"]
	if kind != "" && name != "" {
		return fmt.Sprintf("%s/%s", kind, name), nil
	}
	return "", fmt.Errorf("%w: ConfigAuditReport %q has no ownerReferences and no trivy-operator resource labels", errInvalidReport, report.Name)
}

// Server holds AWS clients and request-independent identity resolved once at startup.
type Server struct {
	cfg                   Config
	securityHub           *securityhub.Client
	reconcilerSecurityHub *securityhub.Client
	accountID             string
	region                string
	productArn            string
	now                   func() time.Time
	ignorePath            string
	ignore                *ignore.IgnoreConfig
}

// NewServer resolves the caller identity via STS and constructs the Security Hub clients.
// A second SecurityHub client is built for the reconciler with adaptive
// rate-limiting and a higher retry budget — that's a background job with no
// latency budget, unlike the request path. If now is nil it defaults to
// time.Now; tests inject a fixed clock for deterministic expiry pruning.
func NewServer(ctx context.Context, awsCfg aws.Config, cfg Config, now func() time.Time) (*Server, error) {
	if now == nil {
		now = time.Now
	}
	stsClient := sts.NewFromConfig(awsCfg)
	callerIdentity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("failed to get caller identity: %w", err)
	}
	region := awsCfg.Region
	ignoreCfg, err := ignore.LoadIgnoreFile(cfg.IgnoreFile, now())
	if err != nil {
		return nil, fmt.Errorf("loading ignore file: %w", err)
	}
	if cfg.IgnoreFile != "" {
		log.Printf("Loaded %d active rule(s) from %s", len(ignoreCfg.Vulnerabilities), cfg.IgnoreFile)
	}
	return &Server{
		cfg:         cfg,
		securityHub: securityhub.NewFromConfig(awsCfg),
		reconcilerSecurityHub: securityhub.NewFromConfig(awsCfg, func(o *securityhub.Options) {
			o.Retryer = retry.NewAdaptiveMode(func(ao *retry.AdaptiveModeOptions) {
				ao.StandardOptions = append(ao.StandardOptions, func(so *retry.StandardOptions) {
					so.MaxAttempts = 10
				})
			})
		}),
		accountID:  aws.ToString(callerIdentity.Account),
		region:     region,
		productArn: fmt.Sprintf("arn:aws:securityhub:%s::product/aquasecurity/aquasecurity", region),
		now:        now,
		ignorePath: cfg.IgnoreFile,
		ignore:     ignoreCfg,
	}, nil
}

// Routes returns a router with the healthz and webhook endpoints registered.
func (s *Server) Routes() *mux.Router {
	r := mux.NewRouter()

	r.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("OK"))
		if err != nil {
			log.Printf("Error writing response: %v", err)
		}
	}).Methods("GET")

	r.HandleFunc("/trivy-webhook", s.ProcessTrivyWebhook()).Methods("POST")

	return r
}

// ProcessTrivyWebhook processes incoming vulnerability reports
func (s *Server) ProcessTrivyWebhook() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var report webhook

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Error reading request body", http.StatusBadRequest)
			log.Printf("Error reading request body: %v", err)
			return
		}

		if len(body) == 0 {
			http.Error(w, "Empty request body", http.StatusBadRequest)
			log.Printf("Empty request body")
			return
		}

		verb := verbUpdate
		var envelope webhookMsg
		if err := json.Unmarshal(body, &envelope); err == nil && envelope.Verb != "" && len(envelope.OperatorObject) > 0 {
			verb = envelope.Verb
			body = envelope.OperatorObject
		}

		if verb != verbUpdate && verb != verbDelete {
			log.Printf("Ignoring webhook with unknown verb %q", verb)
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte("Ignored unknown verb")); err != nil {
				log.Printf("Error writing response: %v", err)
			}
			return
		}

		err = json.Unmarshal(body, &report)
		if err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			log.Printf("Error decoding JSON: %v", err)
			return
		}

		processingFailed := func(err error) bool {
			if err == nil {
				return false
			}
			if errors.Is(err, errInvalidReport) {
				http.Error(w, err.Error(), http.StatusBadRequest)
				log.Printf("Invalid report: %v", err)
				return true
			}
			http.Error(w, "Error processing report", http.StatusInternalServerError)
			log.Printf("Error processing report: %v", err)
			return true
		}

		var findings []types.AwsSecurityFinding
		switch report.Kind {
		case "ConfigAuditReport":
			if s.cfg.ConfigAuditEnable {
				findings, err = s.getConfigAuditReportFindings(body)
				if processingFailed(err) {
					return
				}
			}
		case "InfraAssessmentReport":
			if s.cfg.InfraAssessmentEnable {
				findings, err = s.getInfraAssessmentReport(body)
				if processingFailed(err) {
					return
				}
			}
		case "ClusterComplianceReport":
			if s.cfg.ClusterComplianceEnable {
				findings, err = s.getClusterComplianceReport(body)
				if processingFailed(err) {
					return
				}
			}
		case "VulnerabilityReport":
			if s.cfg.VulnerabilityEnable {
				findings, err = s.getVulnerabilityReportFindings(body)
				if processingFailed(err) {
					return
				}
			}
		default:
			http.Error(w, "unknown report type", http.StatusBadRequest)
			log.Printf("unknown report type: %s", report.Kind)
			return
		}

		if verb == verbDelete {
			for i := range findings {
				findings[i].RecordState = types.RecordStateArchived
			}
		}

		err = s.importFindingsToSecurityHub(r.Context(), findings)
		if err != nil {
			http.Error(w, "Error importing findings to Security Hub", http.StatusInternalServerError)
			log.Printf("Error importing findings to Security Hub: %v", err)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, err = w.Write([]byte("Report processed"))
		if err != nil {
			log.Printf("Error writing response: %v", err)
		}
	}
}

func (s *Server) getConfigAuditReportFindings(body []byte) ([]types.AwsSecurityFinding, error) {
	configAuditReport := &v1alpha1.ConfigAuditReport{}

	err := json.Unmarshal(body, &configAuditReport)
	if err != nil {
		return nil, fmt.Errorf("error decoding JSON: %v", err)
	}

	log.Printf("Processing report: %s", configAuditReport.Name)

	target, err := resolveConfigAuditTarget(configAuditReport)
	if err != nil {
		return nil, err
	}

	var findings []types.AwsSecurityFinding
	now := s.now().Format(time.RFC3339)

	for _, check := range configAuditReport.Report.Checks {
		severity := remapSeverity(check.Severity)
		description := truncateDescription(check.Description)

		other := map[string]string{}
		if len(check.Messages) > 0 {
			other["Message"] = strings.Join(check.Messages, "\n")
		}

		findings = append(findings, types.AwsSecurityFinding{
			SchemaVersion: aws.String("2018-10-08"),
			Id:            aws.String(fmt.Sprintf("%s-%s", check.ID, target)),
			ProductArn:    aws.String(s.productArn),
			GeneratorId:   aws.String(fmt.Sprintf("Trivy/%s", check.ID)),
			AwsAccountId:  aws.String(s.accountID),
			Types:         []string{"Software and Configuration Checks"},
			CreatedAt:     aws.String(now),
			UpdatedAt:     aws.String(now),
			Severity:      &types.Severity{Label: types.SeverityLabel(severity)},
			Title:         aws.String(fmt.Sprintf("Trivy found a misconfiguration in %s: %s", target, check.Title)),
			Description:   aws.String(description),
			Remediation: &types.Remediation{
				Recommendation: &types.Recommendation{
					Text: aws.String(check.Remediation),
				},
			},
			ProductFields: trivyProductFields,
			Resources: []types.Resource{
				{
					Type:      aws.String("Other"),
					Id:        aws.String(target),
					Partition: types.PartitionAws,
					Region:    aws.String(s.region),
					Details: &types.ResourceDetails{
						Other: other,
					},
				},
			},
			RecordState: types.RecordStateActive,
		})
	}

	return findings, nil
}

func (s *Server) getInfraAssessmentReport(body []byte) ([]types.AwsSecurityFinding, error) {
	infraAssessmentReport := &v1alpha1.InfraAssessmentReport{}

	err := json.Unmarshal(body, &infraAssessmentReport)
	if err != nil {
		return nil, fmt.Errorf("error decoding JSON: %v", err)
	}

	log.Printf("Processing report: %s", infraAssessmentReport.Name)

	reportJSON, err := json.MarshalIndent(infraAssessmentReport, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("error encoding JSON: %v", err)
	}
	log.Printf("Report: %s", reportJSON)

	var findings []types.AwsSecurityFinding
	return findings, nil
}

func (s *Server) getClusterComplianceReport(body []byte) ([]types.AwsSecurityFinding, error) {
	clusterComplianceReport := &v1alpha1.ClusterComplianceReport{}

	err := json.Unmarshal(body, &clusterComplianceReport)
	if err != nil {
		return nil, fmt.Errorf("error decoding JSON: %v", err)
	}

	log.Printf("Processing report: %s", clusterComplianceReport.Name)

	reportJSON, err := json.MarshalIndent(clusterComplianceReport, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("error encoding JSON: %v", err)
	}
	log.Printf("Report: %s", reportJSON)

	var findings []types.AwsSecurityFinding
	return findings, nil
}

func (s *Server) getVulnerabilityReportFindings(body []byte) ([]types.AwsSecurityFinding, error) {
	vulnerabilityReport := &v1alpha1.VulnerabilityReport{}

	err := json.Unmarshal(body, &vulnerabilityReport)
	if err != nil {
		return nil, fmt.Errorf("error decoding JSON: %v", err)
	}

	log.Printf("Processing report: %s", vulnerabilityReport.Name)

	Container := vulnerabilityReport.Labels["trivy-operator.container.name"]
	Registry := vulnerabilityReport.Report.Registry.Server
	Repository := vulnerabilityReport.Report.Artifact.Repository
	Digest := vulnerabilityReport.Report.Artifact.Digest
	FullImageName := fmt.Sprintf("%s/%s@%s", Registry, Repository, Digest)
	Tag := vulnerabilityReport.Report.Artifact.Tag
	if Digest == "" {
		FullImageName = fmt.Sprintf("%s/%s:%s", Registry, Repository, Tag)
	}

	ImageName := fmt.Sprintf("%s/%s", Registry, Repository)

	var findings []types.AwsSecurityFinding
	now := s.now().Format(time.RFC3339)

	for _, vulnerabilities := range vulnerabilityReport.Report.Vulnerabilities {
		severity := remapSeverity(vulnerabilities.Severity)
		description := vulnerabilities.Description
		if description == "" {
			description = vulnerabilities.Title
		}
		description = truncateDescription(description)

		productFields := map[string]string{"Product Name": "Trivy"}
		var workflow *types.Workflow
		var note *types.Note
		if match := s.ignore.MatchVulnerability(vulnerabilities.VulnerabilityID, vulnerabilities.Target, vulnerabilities.PkgPath); match != nil {
			workflow = &types.Workflow{Status: types.WorkflowStatusSuppressed}
			note = &types.Note{
				Text:      aws.String(buildSuppressionNote(match)),
				UpdatedBy: aws.String("trivy-webhook"),
				UpdatedAt: aws.String(now),
			}
			productFields[trivyIgnoreRuleIDKey] = match.ID
		}

		findings = append(findings, types.AwsSecurityFinding{
			SchemaVersion: aws.String("2018-10-08"),
			Id:            aws.String(fmt.Sprintf("%s-%s", FullImageName, vulnerabilities.VulnerabilityID)),
			ProductArn:    aws.String(s.productArn),
			GeneratorId:   aws.String(fmt.Sprintf("Trivy/%s", vulnerabilities.VulnerabilityID)),
			AwsAccountId:  aws.String(s.accountID),
			Types:         []string{"Software and Configuration Checks/Vulnerabilities/CVE"},
			CreatedAt:     aws.String(now),
			UpdatedAt:     aws.String(now),
			Severity:      &types.Severity{Label: types.SeverityLabel(severity)},
			Title:         aws.String(fmt.Sprintf("%s/%s:%s %s", ImageName, Container, Tag, vulnerabilities.VulnerabilityID)),
			Description:   aws.String(description),
			Remediation: &types.Remediation{
				Recommendation: &types.Recommendation{
					Text: aws.String("Upgrade to version " + vulnerabilities.FixedVersion),
					Url:  aws.String(vulnerabilities.PrimaryLink),
				},
			},
			ProductFields: productFields,
			Resources: []types.Resource{
				{
					Type:      aws.String("Container"),
					Id:        aws.String(ImageName),
					Partition: types.PartitionAws,
					Region:    aws.String(s.region),
					Details: &types.ResourceDetails{
						Other: map[string]string{
							"Container Image":   ImageName,
							"CVE ID":            vulnerabilities.VulnerabilityID,
							"CVE Title":         vulnerabilities.Title,
							"PkgName":           vulnerabilities.Resource,
							"Installed Package": vulnerabilities.InstalledVersion,
							"Patched Package":   vulnerabilities.FixedVersion,
							"NvdCvssScoreV3":    fmt.Sprintf("%f", tools.GetVulnScore(vulnerabilities)),
							"NvdCvssVectorV3":   "",
							"Vuln Target":       vulnerabilities.Target,
							"Pkg Path":          vulnerabilities.PkgPath,
						},
					},
				},
			},
			RecordState: types.RecordStateActive,
			Workflow:    workflow,
			Note:        note,
		})
	}

	return findings, nil
}

// buildSuppressionNote renders the trivy ignore rule into a human-readable
// note for the Security Hub finding. Capped at 512 chars (Security Hub limit).
func buildSuppressionNote(rule *ignore.IgnoreFinding) string {
	stmt := rule.Statement
	if stmt == "" {
		stmt = "(no statement)"
	}
	expires := "never"
	if !rule.ExpiredAt.IsZero() {
		expires = rule.ExpiredAt.Format(time.RFC3339)
	}
	text := fmt.Sprintf("Suppressed by trivy ignore rule %s. Statement: %s. Expires: %s", rule.ID, stmt, expires)
	if len(text) > 512 {
		text = text[:509] + "..."
	}
	return text
}

// Import findings to AWS Security Hub in batches of 100
func (s *Server) importFindingsToSecurityHub(ctx context.Context, findings []types.AwsSecurityFinding) error {
	batchSize := 100
	for i := 0; i < len(findings); i += batchSize {
		end := min(i+batchSize, len(findings))

		batch := findings[i:end]

		input := &securityhub.BatchImportFindingsInput{
			Findings: batch,
		}

		_, err := s.securityHub.BatchImportFindings(ctx, input)
		if err != nil {
			return fmt.Errorf("error importing findings to Security Hub: %v", err)
		}
	}

	log.Printf("%d Findings imported to Security Hub", len(findings))
	return nil
}

func main() {
	// overwrite trivy library logging configurations.
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags)

	cfg := LoadConfig()
	PrintConfig(cfg)

	startupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	awsCfg, err := config.LoadDefaultConfig(startupCtx)
	if err != nil {
		log.Fatalf("unable to load AWS SDK config: %v", err)
	}

	srv, err := NewServer(startupCtx, awsCfg, cfg, time.Now)
	if err != nil {
		log.Fatalf("unable to create server: %v", err)
	}

	rootCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.IgnoreFile != "" && cfg.ReconcileInterval > 0 {
		go srv.runReconciler(rootCtx)
	} else if cfg.IgnoreFile != "" {
		log.Printf("Ignore file configured but reconciler disabled (IGNORE_RECONCILE_INTERVAL=0); stale suppressions will not be lifted automatically")
	}

	port := ":8080"
	log.Printf("Starting server on port %s", port)
	httpSrv := &http.Server{Addr: port, Handler: srv.Routes()}
	go func() {
		<-rootCtx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := httpSrv.Shutdown(shutdownCtx); err != nil {
			log.Printf("HTTP shutdown: %v", err)
		}
	}()
	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
