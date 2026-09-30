package buildinfo

/*
Apache License 2.0

Copyright 2026 Shane

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import (
	"runtime/debug"
	"testing"
)

func vcsInfo(rev, when, modified string) *debug.BuildInfo {
	return &debug.BuildInfo{Settings: []debug.BuildSetting{
		{Key: "vcs.revision", Value: rev},
		{Key: "vcs.time", Value: when},
		{Key: "vcs.modified", Value: modified},
	}}
}

func TestResolveStampedWins(t *testing.T) {
	got := resolve("v1.2.3", "abc123", "2026-09-25T00:00:00Z", vcsInfo("fff", "2020-01-01T00:00:00Z", "true"))
	want := Info{Version: "v1.2.3", Commit: "abc123", BuildDate: "2026-09-25T00:00:00Z"}
	if got != want {
		t.Errorf("resolve = %+v, want %+v", got, want)
	}
}

func TestResolveFallsBackToVCS(t *testing.T) {
	got := resolve(devVersion, "", "", vcsInfo("0123456789abcdef", "2026-09-24T12:00:00Z", "true"))
	want := Info{Version: devVersion, Commit: "0123456789abcdef-dirty", BuildDate: "2026-09-24T12:00:00Z"}
	if got != want {
		t.Errorf("resolve = %+v, want %+v", got, want)
	}
}

func TestResolveNoMetadata(t *testing.T) {
	got := resolve(devVersion, "", "", nil)
	want := Info{Version: devVersion, Commit: unknown, BuildDate: unknown}
	if got != want {
		t.Errorf("resolve = %+v, want %+v", got, want)
	}
}

func TestGetUsesPackageVars(t *testing.T) {
	old := [3]string{Version, Commit, BuildDate}
	t.Cleanup(func() { Version, Commit, BuildDate = old[0], old[1], old[2] })
	Version, Commit, BuildDate = "v9.9.9", "deadbeef", "2026-01-01T00:00:00Z"
	if got := Get(); got.Version != "v9.9.9" || got.Commit != "deadbeef" || got.BuildDate != "2026-01-01T00:00:00Z" {
		t.Errorf("Get = %+v", got)
	}
}
