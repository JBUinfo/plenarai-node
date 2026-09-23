package auth

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/spf13/viper"
)

// Separate CLI processes must not share a participant's credentials.
func TestParticipantCredentialsStayInTheirDirectory(t *testing.T) {
	t.Cleanup(viper.Reset)
	root := t.TempDir()
	for _, name := range []string{"responder", "judge"} {
		viper.Reset()
		t.Setenv("PLENARAI_CONFIG_DIR", filepath.Join(root, name))
		if err := SaveTokens(&TokenPair{AccessToken: name, RefreshToken: name + "-refresh"}); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"judge", "responder"} {
		viper.Reset()
		t.Setenv("PLENARAI_CONFIG_DIR", filepath.Join(root, name))
		tokens, err := LoadTokens()
		if err != nil || tokens.AccessToken != name || tokens.RefreshToken != name+"-refresh" {
			t.Fatalf("profile %s: tokens=%+v err=%v", name, tokens, err)
		}
	}
	viper.Reset()
	viper.AddConfigPath(filepath.Join(root, "responder"))
	t.Setenv("PLENARAI_CONFIG_DIR", filepath.Join(root, "missing"))
	if _, err := LoadTokens(); err == nil {
		t.Fatal("missing profile inherited another participant's credentials")
	}
}

func TestSaveTokensTightensUnixPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits do not configure Windows ACLs")
	}
	t.Cleanup(viper.Reset)
	dir := filepath.Join(t.TempDir(), "profile")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PLENARAI_CONFIG_DIR", dir)
	viper.Reset()
	if err := SaveTokens(&TokenPair{AccessToken: "access", RefreshToken: "refresh"}); err != nil {
		t.Fatal(err)
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("config directory mode = %04o, want 0700", got)
	}
	fileInfo, err := os.Stat(filepath.Join(dir, configFileName))
	if err != nil {
		t.Fatal(err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("config file mode = %04o, want 0600", got)
	}
}

func TestSaveTokensRejectsSymlinkedConfigDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions vary on Windows")
	}
	t.Cleanup(viper.Reset)
	root := t.TempDir()
	link := filepath.Join(root, "profile")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PLENARAI_CONFIG_DIR", link)
	viper.Reset()
	if err := SaveTokens(&TokenPair{AccessToken: "access", RefreshToken: "refresh"}); err == nil {
		t.Fatal("SaveTokens followed a symlinked config directory")
	}
}

func TestSaveTokensRejectsSymlinkedConfigFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions vary on Windows")
	}
	t.Cleanup(viper.Reset)
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "target.yaml")
	if err := os.WriteFile(target, []byte("keep: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, configFileName)); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PLENARAI_CONFIG_DIR", dir)
	viper.Reset()
	if err := SaveTokens(&TokenPair{AccessToken: "access", RefreshToken: "refresh"}); err == nil {
		t.Fatal("SaveTokens followed a symlinked config file")
	}
}
