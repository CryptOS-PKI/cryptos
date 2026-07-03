package init

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
