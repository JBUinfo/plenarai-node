//go:build windows

package auth

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/windows"
)

// Windows ignores Unix permission bits. Replace inherited and explicit grants
// with a protected DACL for this account, local SYSTEM and administrators.
func secureNativeConfigPermissions(path string, directory bool) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("current Windows user: %w", err)
	}
	if user == nil || user.User.Sid == nil {
		return fmt.Errorf("current Windows user has no SID")
	}
	flags := ""
	if directory {
		flags = "OICI" // Restrict files and subdirectories created below it too.
	}
	ace := func(sid string) string {
		return "(A;" + flags + ";GA;;;" + sid + ")"
	}
	sd, err := windows.SecurityDescriptorFromString("D:P" + ace(user.User.Sid.String()) + ace("SY") + ace("BA"))
	if err != nil {
		return fmt.Errorf("build protected Windows ACL: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read protected Windows ACL: %w", err)
	}
	err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil)
	runtime.KeepAlive(sd)
	if err != nil {
		return fmt.Errorf("set protected Windows ACL: %w", err)
	}
	return nil
}
