//go:build goexperiment.runtimesecret && linux && (amd64 || arm64)

package security

import (
	"runtime/secret"
	"testing"
)

func TestDoSecretEnablesRuntimeSecret(t *testing.T) {
	if !RuntimeSecretAvailable() {
		t.Fatal("runtime/secret build reported itself unavailable")
	}

	enabledInside := false
	DoSecret(func() {
		enabledInside = secret.Enabled()
	})
	if !enabledInside {
		t.Fatal("secret.Enabled was false inside DoSecret")
	}
}
