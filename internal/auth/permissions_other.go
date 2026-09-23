//go:build !windows

package auth

func secureNativeConfigPermissions(_ string, _ bool) error { return nil }
