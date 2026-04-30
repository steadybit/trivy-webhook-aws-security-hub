// Package testutil provides a fake AWS endpoint for HTTP-level testing.
// It speaks awsJson1.1 for SecurityHub and the Query protocol for STS,
// captures BatchImportFindings inputs, and supports per-call error injection.
package testutil

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
)

// AWSError configures an error response from the fake.
type AWSError struct {
	StatusCode int
	Type       string
	Message    string
}

// FakeAWS is a single-server fake that demuxes between SecurityHub and STS
// based on request shape. Configure error injection on the public fields
// before invoking the system under test; field reads are not synchronised
// because tests configure before triggering.
type FakeAWS struct {
	t      *testing.T
	server *httptest.Server

	mu           sync.Mutex
	batchImports []securityhub.BatchImportFindingsInput

	Account string
	Region  string

	STSError *AWSError

	// SecurityHubErrorOnCall, if > 0, makes the Nth BatchImportFindings call
	// (1-indexed) and every subsequent call return SecurityHubError instead
	// of success. Sticky semantics matter because the SDK retries on 5xx; if
	// only the first call failed, retries would silently succeed.
	SecurityHubErrorOnCall int
	SecurityHubError       *AWSError
}

func NewFakeAWS(t *testing.T) *FakeAWS {
	t.Helper()
	f := &FakeAWS{
		t:       t,
		Account: "123456789012",
		Region:  "us-east-1",
	}
	f.server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

// Config returns an aws.Config that points all SDK clients at the fake.
func (f *FakeAWS) Config() aws.Config {
	return aws.Config{
		Region:       f.Region,
		Credentials:  aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider("test", "test", "")),
		BaseEndpoint: aws.String(f.server.URL),
	}
}

// URL returns the fake's base URL — useful when overriding a single client's endpoint.
func (f *FakeAWS) URL() string {
	return f.server.URL
}

// BatchImports returns a snapshot of every BatchImportFindings input received.
func (f *FakeAWS) BatchImports() []securityhub.BatchImportFindingsInput {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]securityhub.BatchImportFindingsInput, len(f.batchImports))
	copy(out, f.batchImports)
	return out
}

func (f *FakeAWS) serve(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/findings/import":
		f.serveSecurityHub(w, r)
		return
	case "/", "":
		if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
			f.serveSTS(w, r)
			return
		}
	}

	f.t.Errorf("FakeAWS: unrecognized request: method=%s path=%s headers=%v", r.Method, r.URL.Path, r.Header)
	http.Error(w, "unrecognized AWS request", http.StatusBadRequest)
}

func (f *FakeAWS) serveSecurityHub(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		f.t.Errorf("FakeAWS: read body: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var input securityhub.BatchImportFindingsInput
	if err := json.Unmarshal(body, &input); err != nil {
		f.t.Errorf("FakeAWS: decode BatchImportFindings input: %v\nbody=%s", err, body)
		f.writeJSONError(w, http.StatusBadRequest, "InvalidInputException", err.Error())
		return
	}

	f.mu.Lock()
	f.batchImports = append(f.batchImports, input)
	callNum := len(f.batchImports)
	f.mu.Unlock()

	if f.SecurityHubError != nil && f.SecurityHubErrorOnCall > 0 && callNum >= f.SecurityHubErrorOnCall {
		f.writeJSONError(w, f.SecurityHubError.StatusCode, f.SecurityHubError.Type, f.SecurityHubError.Message)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"FailedCount":0,"SuccessCount":%d,"FailedFindings":[]}`, len(input.Findings))
}

func (f *FakeAWS) serveSTS(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	action := r.Form.Get("Action")
	if action != "GetCallerIdentity" {
		f.t.Errorf("FakeAWS: unexpected STS action: %s", action)
		f.writeXMLError(w, http.StatusBadRequest, "InvalidAction", "unknown action: "+action)
		return
	}

	if f.STSError != nil {
		f.writeXMLError(w, f.STSError.StatusCode, f.STSError.Type, f.STSError.Message)
		return
	}

	w.Header().Set("Content-Type", "text/xml")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:iam::%[1]s:user/test</Arn>
    <UserId>AIDACKCEVSQ6C2EXAMPLE</UserId>
    <Account>%[1]s</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata>
    <RequestId>00000000-0000-0000-0000-000000000000</RequestId>
  </ResponseMetadata>
</GetCallerIdentityResponse>`, f.Account)
}

func (f *FakeAWS) writeJSONError(w http.ResponseWriter, status int, typ, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Amzn-Errortype", typ)
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"__type":%q,"message":%q}`, typ, msg)
}

func (f *FakeAWS) writeXMLError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "text/xml")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<ErrorResponse><Error><Type>Sender</Type><Code>%s</Code><Message>%s</Message></Error></ErrorResponse>`, code, msg)
}
