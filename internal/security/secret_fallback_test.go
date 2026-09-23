//go:build !goexperiment.runtimesecret || !linux || (!amd64 && !arm64)

package security

import "testing"

func TestFallbackReportsRuntimeSecretUnavailable(t *testing.T) {
	if RuntimeSecretAvailable() {
		t.Fatal("fallback build reported runtime/secret as available")
	}
}
