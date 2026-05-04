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
	log.Printf("Reconciler started (interval=%s, ignoreFile=%s)", s.cfg.ReconcileInterval, s.ignorePath)
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
	cfg, err := ignore.LoadIgnoreFile(s.ignorePath, s.now())
	if err != nil {
		log.Printf("reconcile: load ignore file: %v", err)
		return
	}

	filters := &types.AwsSecurityFindingFilters{
		ProductArn: []types.StringFilter{{
			Comparison: types.StringFilterComparisonEquals,
			Value:      aws.String(s.productArn),
		}},
		WorkflowStatus: []types.StringFilter{{
			Comparison: types.StringFilterComparisonEquals,
			Value:      aws.String(string(types.WorkflowStatusSuppressed)),
		}},
		RecordState: []types.StringFilter{{
			Comparison: types.StringFilterComparisonEquals,
			Value:      aws.String(string(types.RecordStateActive)),
		}},
	}

	paginator := securityhub.NewGetFindingsPaginator(s.reconcilerSecurityHub, &securityhub.GetFindingsInput{
		Filters: filters,
	})

	var toUpdate []types.AwsSecurityFindingIdentifier
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			log.Printf("reconcile: GetFindings: %v", err)
			break
		}
		for _, f := range page.Findings {
			ruleID, ok := f.ProductFields[trivyIgnoreRuleIDKey]
			if !ok || ruleID == "" {
				// Not one of ours — could be a manual console suppression. Leave it.
				continue
			}
			vulnID, target, pkgPath := extractMatchKeys(f)
			if cfg.MatchVulnerability(vulnID, target, pkgPath) != nil {
				continue
			}
			toUpdate = append(toUpdate, types.AwsSecurityFindingIdentifier{
				Id:         f.Id,
				ProductArn: f.ProductArn,
			})
		}
	}

	if len(toUpdate) == 0 {
		log.Printf("reconcile: 0 findings to un-suppress")
		return
	}

	log.Printf("reconcile: un-suppressing %d finding(s)", len(toUpdate))
	updateNote := &types.NoteUpdate{
		Text:      aws.String("Un-suppressed: ignore rule expired or removed"),
		UpdatedBy: aws.String("trivy-webhook"),
	}
	workflowUpdate := &types.WorkflowUpdate{Status: types.WorkflowStatusNew}
	const batchSize = 100
	for i := 0; i < len(toUpdate); i += batchSize {
		end := min(i+batchSize, len(toUpdate))
		_, err := s.reconcilerSecurityHub.BatchUpdateFindings(ctx, &securityhub.BatchUpdateFindingsInput{
			FindingIdentifiers: toUpdate[i:end],
			Note:               updateNote,
			Workflow:           workflowUpdate,
		})
		if err != nil {
			log.Printf("reconcile: BatchUpdateFindings: %v", err)
			// keep going — partial progress is better than zero
		}
	}
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
	return other["CVE ID"], other["Vuln Target"], other["Pkg Path"]
}
