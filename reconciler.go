package main

import (
	"context"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"

	"github.com/csepulveda/trivy-webhook-aws-security-hub/internal/ignore"
)

const reconcileBatchSize = 100

// runReconciler periodically pages through Security Hub for findings that we
// previously suppressed and re-activates any whose ignore rule has expired or
// been removed from the file. It runs one pass eagerly on startup (so a
// freshly-deployed pod with edits to the ignore file does not wait for the
// full interval), then ticks at cfg.ReconcileInterval.
//
// The loop never exits while ctx is alive: every operation that can fail
// (file read, GetFindings, BatchUpdateFindings) logs and the next tick fires
// normally. This is intentional — a transient AWS error or a temporarily
// broken ignore file should not silently disable un-suppression for the
// lifetime of the pod.
func (s *Server) runReconciler(ctx context.Context) {
	log.Printf("Reconciler started (interval=%s, ignoreFile=%s)", s.cfg.ReconcileInterval, s.cfg.IgnoreFile)
	s.reconcileOnce(ctx)
	ticker := time.NewTicker(s.cfg.ReconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("Reconciler stopping: %v", ctx.Err())
			return
		case <-ticker.C:
			s.reconcileOnce(ctx)
		}
	}
}

// reconcileOnce performs a single reconciliation pass. All errors are logged
// and swallowed — see runReconciler for the rationale.
func (s *Server) reconcileOnce(ctx context.Context) {
	cfg, err := ignore.LoadIgnoreFile(s.cfg.IgnoreFile, s.now())
	if err != nil {
		log.Printf("reconcile: load ignore file: %v", err)
		return
	}

	paginator := securityhub.NewGetFindingsPaginator(s.reconcilerSecurityHub, &securityhub.GetFindingsInput{
		Filters: &types.AwsSecurityFindingFilters{
			ProductArn:     equalsFilter(s.productArn),
			WorkflowStatus: equalsFilter(string(types.WorkflowStatusSuppressed)),
			RecordState:    equalsFilter(string(types.RecordStateActive)),
		},
	})

	noteUpdate := &types.NoteUpdate{
		Text:      aws.String("Un-suppressed: ignore rule expired or removed"),
		UpdatedBy: aws.String(trivyWebhookUpdater),
	}
	workflowUpdate := &types.WorkflowUpdate{Status: types.WorkflowStatusNew}

	batch := make([]types.AwsSecurityFindingIdentifier, 0, reconcileBatchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		_, err := s.reconcilerSecurityHub.BatchUpdateFindings(ctx, &securityhub.BatchUpdateFindingsInput{
			FindingIdentifiers: batch,
			Note:               noteUpdate,
			Workflow:           workflowUpdate,
		})
		if err != nil {
			log.Printf("reconcile: BatchUpdateFindings: %v", err)
		}
		batch = batch[:0]
	}

	total := 0
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			log.Printf("reconcile: GetFindings: %v", err)
			break
		}
		for _, f := range page.Findings {
			ruleID, ok := f.ProductFields[trivyIgnoreRuleIDKey]
			if !ok || ruleID == "" {
				continue
			}
			vulnID, target, pkgPath := extractMatchKeys(f)
			if cfg.MatchVulnerability(vulnID, target, pkgPath) != nil {
				continue
			}
			batch = append(batch, types.AwsSecurityFindingIdentifier{
				Id:         f.Id,
				ProductArn: f.ProductArn,
			})
			total++
			if len(batch) == reconcileBatchSize {
				flush()
			}
		}
	}
	flush()

	if total == 0 {
		log.Printf("reconcile: 0 findings to un-suppress")
	} else {
		log.Printf("reconcile: un-suppressed %d finding(s)", total)
	}
}

// equalsFilter is a one-line constructor for the Security Hub filter shape
// used three times above.
func equalsFilter(value string) []types.StringFilter {
	return []types.StringFilter{{
		Comparison: types.StringFilterComparisonEquals,
		Value:      aws.String(value),
	}}
}

// extractMatchKeys recovers the values needed to re-evaluate the ignore rules
// against an existing finding. The webhook stores them under the noted keys
// in Resources[0].Details.Other; older findings (from before this feature
// landed) won't have Vuln Target / Pkg Path set, in which case we pass empty
// strings and rules without path constraints will still match correctly.
func extractMatchKeys(f types.AwsSecurityFinding) (vulnID, target, pkgPath string) {
	if len(f.Resources) == 0 || f.Resources[0].Details == nil {
		return "", "", ""
	}
	other := f.Resources[0].Details.Other
	return other[cveIDKey], other[vulnTargetKey], other[pkgPathKey]
}
