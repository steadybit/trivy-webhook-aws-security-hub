package tools

import (
	"os"
	"testing"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
)

func TestGetVulnScore(t *testing.T) {
	cases := map[string]struct {
		vuln v1alpha1.Vulnerability
		want float64
	}{
		"score set":  {v1alpha1.Vulnerability{Score: float64Ptr(7.5)}, 7.5},
		"score nil":  {v1alpha1.Vulnerability{Score: nil}, 0.0},
		"score zero": {v1alpha1.Vulnerability{Score: float64Ptr(0.0)}, 0.0},
		"score 9.8":  {v1alpha1.Vulnerability{Score: float64Ptr(9.8)}, 9.8},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := GetVulnScore(tc.vuln); got != tc.want {
				t.Errorf("GetVulnScore = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseEnvBool(t *testing.T) {
	const key = "TRIVY_WEBHOOK_TEST_BOOL"

	cases := []struct {
		name       string
		setValue   string
		unset      bool
		defaultVal bool
		want       bool
	}{
		{name: "unset returns default true", unset: true, defaultVal: true, want: true},
		{name: "unset returns default false", unset: true, defaultVal: false, want: false},
		{name: "true overrides default false", setValue: "true", defaultVal: false, want: true},
		{name: "false overrides default true", setValue: "false", defaultVal: true, want: false},
		{name: "1 parses as true", setValue: "1", defaultVal: false, want: true},
		{name: "0 parses as false", setValue: "0", defaultVal: true, want: false},
		{name: "malformed returns default true", setValue: "yesplease", defaultVal: true, want: true},
		{name: "malformed returns default false", setValue: "noway", defaultVal: false, want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(key, "tracked-for-cleanup")
			if tc.unset {
				if err := os.Unsetenv(key); err != nil {
					t.Fatalf("os.Unsetenv: %v", err)
				}
			} else {
				t.Setenv(key, tc.setValue)
			}
			if got := ParseEnvBool(key, tc.defaultVal); got != tc.want {
				t.Errorf("ParseEnvBool(%q, %v) = %v, want %v", key, tc.defaultVal, got, tc.want)
			}
		})
	}
}

func float64Ptr(v float64) *float64 { return &v }
