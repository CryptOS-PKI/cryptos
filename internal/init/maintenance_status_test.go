package init

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
	"context"
	"testing"
)

func TestMaintenanceStatus(t *testing.T) {
	p := newMaintenanceStatus("phase-1-dev")
	st, err := p.Status(context.Background())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st == nil {
		t.Fatal("nil status")
	}
	if st.SoftwareVersion != "phase-1-dev" {
		t.Errorf("SoftwareVersion = %q, want phase-1-dev", st.SoftwareVersion)
	}
	if st.BootCount != 0 {
		t.Errorf("BootCount = %d, want 0 (no state store in maintenance)", st.BootCount)
	}
}
