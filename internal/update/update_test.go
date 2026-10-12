package update

import "testing"

func TestIsNewerUsesSemanticVersionOrdering(t *testing.T) {
	tests := []struct {
		name            string
		latest, current string
		want            bool
	}{
		{name: "patch increment", latest: "v1.2.4", current: "1.2.3", want: true},
		{name: "minor downgrade", latest: "1.2.0", current: "v1.3.0", want: false},
		{name: "equal ignores build metadata", latest: "1.2.3+release", current: "v1.2.3+other", want: false},
		{name: "release newer than prerelease", latest: "1.2.3", current: "1.2.3-rc.1", want: true},
		{name: "prerelease ordering", latest: "1.2.3-rc.2", current: "1.2.3-rc.1", want: true},
		{name: "numeric prerelease precedes text", latest: "1.2.3-beta", current: "1.2.3-1", want: true},
		{name: "invalid latest", latest: "release-1.2.4", current: "1.2.3", want: false},
		{name: "invalid current", latest: "1.2.4", current: "dev", want: false},
		{name: "leading zero", latest: "1.02.4", current: "1.2.3", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNewer(tt.latest, tt.current); got != tt.want {
				t.Fatalf("isNewer(%q, %q) = %v, want %v", tt.latest, tt.current, got, tt.want)
			}
		})
	}
}

func TestNewestReleaseIncludesPrereleasesAndSkipsDrafts(t *testing.T) {
	releases := []Release{
		{TagName: "v0.1.0-beta.2"},
		{TagName: "v0.1.0-beta.10"},
		{TagName: "v0.2.0-beta.1", Draft: true},
		{TagName: "nightly"},
	}
	if got := newestRelease(releases); got == nil || got.TagName != "v0.1.0-beta.10" {
		t.Fatalf("newestRelease = %+v, want v0.1.0-beta.10", got)
	}
}
