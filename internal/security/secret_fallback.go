//go:build !goexperiment.runtimesecret || !linux || (!amd64 && !arm64)

package security

// DoSecret preserves the same control flow on builds where runtime/secret is
// unavailable. Callers must still explicitly zero sensitive byte slices.
func DoSecret(f func()) {
	f()
}

// RuntimeSecretAvailable reports whether this binary has effective
// runtime/secret support rather than merely accepting the same API.
func RuntimeSecretAvailable() bool {
	return false
}
