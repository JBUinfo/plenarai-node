//go:build goexperiment.runtimesecret && linux && (amd64 || arm64)

package security

import "runtime/secret"

// DoSecret executes f with Go's experimental secret-memory tracking enabled.
func DoSecret(f func()) {
	secret.Do(f)
}

// RuntimeSecretAvailable reports whether this binary was built with effective
// runtime/secret support for its operating system and architecture.
func RuntimeSecretAvailable() bool {
	return true
}
