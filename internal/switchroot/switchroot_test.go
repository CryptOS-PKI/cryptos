package switchroot

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
	"errors"
	"io/fs"
	"strings"
	"testing"
)

type mockSystem struct {
	calls   []string
	loopDev string
	// failts simulate a failure at a given call name.
	failOn   string
	mkdirErr error
}

func (m *mockSystem) record(s string) { m.calls = append(m.calls, s) }

func (m *mockSystem) Mkdir(path string, _ uint32) error {
	m.record("mkdir " + path)
	if m.mkdirErr != nil {
		return m.mkdirErr
	}
	return nil
}

func (m *mockSystem) Mount(source, target, fstype string, flags uintptr, _ string) error {
	m.record("mount " + source + " " + target + " " + fstype)
	if m.failOn == "mount:"+target {
		return errors.New("boom")
	}
	return nil
}

func (m *mockSystem) AttachLoop(backingFile string) (string, error) {
	m.record("attachloop " + backingFile)
	if m.failOn == "attachloop" {
		return "", errors.New("boom")
	}
	return m.loopDev, nil
}

func (m *mockSystem) Chdir(dir string) error  { m.record("chdir " + dir); return nil }
func (m *mockSystem) Chroot(dir string) error { m.record("chroot " + dir); return nil }

func (m *mockSystem) Exec(argv0 string, _, _ []string) error {
	m.record("exec " + argv0)
	if m.failOn == "exec" {
		return errors.New("boom")
	}
	// A real Exec never returns; the mock returns nil and Run reports that
	// as an error, which lets us assert exec was reached.
	return nil
}

func TestRun_Sequence(t *testing.T) {
	m := &mockSystem{loopDev: "/dev/loop0"}
	err := Run(m, nil)
	// Exec "succeeds" in the mock, which Run treats as an error.
	if err == nil || !strings.Contains(err.Error(), "exec returned") {
		t.Fatalf("expected exec-returned error, got %v", err)
	}

	want := []string{
		"mkdir /dev",
		"mount devtmpfs /dev devtmpfs",
		"mkdir /sysroot",
		"attachloop /rootfs.squashfs",
		"mount /dev/loop0 /sysroot squashfs",
		"chdir /sysroot",
		"mount . / ",
		"chroot .",
		"chdir /",
		"exec /init",
	}
	got := strings.Join(m.calls, "|")
	if got != strings.Join(want, "|") {
		t.Errorf("call sequence:\n got %v\nwant %v", m.calls, want)
	}
}

func TestRun_LoopFailureStopsBeforePivot(t *testing.T) {
	m := &mockSystem{loopDev: "/dev/loop0", failOn: "attachloop"}
	if err := Run(m, nil); err == nil {
		t.Fatal("expected error when AttachLoop fails")
	}
	for _, c := range m.calls {
		if strings.HasPrefix(c, "chroot") || strings.HasPrefix(c, "exec") {
			t.Errorf("pivot step %q ran despite loop failure", c)
		}
	}
}

func TestRun_SquashFSMountFailure(t *testing.T) {
	m := &mockSystem{loopDev: "/dev/loop0", failOn: "mount:/sysroot"}
	if err := Run(m, nil); err == nil {
		t.Fatal("expected error when the SquashFS mount fails")
	}
}

func TestRun_ExistingDirsAreOK(t *testing.T) {
	// Mkdir returning fs.ErrExist must not abort the pivot.
	m := &mockSystem{loopDev: "/dev/loop0", mkdirErr: fs.ErrExist}
	if err := Run(m, nil); err == nil || !strings.Contains(err.Error(), "exec returned") {
		t.Fatalf("ErrExist on mkdir should be tolerated, got %v", err)
	}
}
