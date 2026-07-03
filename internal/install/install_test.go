package install

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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type recordedCall struct {
	name string
	args []string
}

type mockRunner struct {
	calls  []recordedCall
	failOn string
}

func (m *mockRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	m.calls = append(m.calls, recordedCall{name, append([]string(nil), args...)})
	if m.failOn != "" && name == m.failOn {
		return []byte("boom"), errors.New("command failed")
	}
	return nil, nil
}

func (m *mockRunner) names() []string {
	var out []string
	for _, c := range m.calls {
		out = append(out, c.name)
	}
	return out
}

// depsRecord captures Deps calls; WaitForDevice is always a no-op so tests
// work without a real block device or root privileges (refs #115).
type depsRecord struct {
	rereadCalls  []string
	mountCalls   [][2]string // [esp, dir]
	unmountCalls []string
}

func (d *depsRecord) deps() Deps {
	return Deps{
		RereadPartitions: func(disk string) error {
			d.rereadCalls = append(d.rereadCalls, disk)
			return nil
		},
		Mount: func(esp, dir string) error {
			d.mountCalls = append(d.mountCalls, [2]string{esp, dir})
			return nil
		},
		Unmount: func(dir string) error {
			d.unmountCalls = append(d.unmountCalls, dir)
			return nil
		},
		// WaitForDevice is a no-op: no real /dev node creation in unit tests.
		WaitForDevice: func(string) error { return nil },
	}
}

// TestPartitionDevice verifies the partition naming for all relevant device
// families (refs #115).
func TestPartitionDevice(t *testing.T) {
	cases := []struct {
		disk string
		part int
		want string
	}{
		// NVMe: name ends in a digit → p-suffix
		{"/dev/nvme0n1", 1, "/dev/nvme0n1p1"},
		{"/dev/nvme0n1", 2, "/dev/nvme0n1p2"},
		// MMC: name ends in a digit → p-suffix
		{"/dev/mmcblk0", 1, "/dev/mmcblk0p1"},
		{"/dev/mmcblk0", 2, "/dev/mmcblk0p2"},
		// Loop: name ends in a digit → p-suffix
		{"/dev/loop0", 1, "/dev/loop0p1"},
		{"/dev/loop0", 2, "/dev/loop0p2"},
		// SCSI / SATA: name ends in a letter → no suffix
		{"/dev/sda", 1, "/dev/sda1"},
		{"/dev/sda", 2, "/dev/sda2"},
		// VirtIO: name ends in a letter → no suffix
		{"/dev/vda", 1, "/dev/vda1"},
		{"/dev/vda", 2, "/dev/vda2"},
	}
	for _, tc := range cases {
		got := partitionDevice(tc.disk, tc.part)
		if got != tc.want {
			t.Errorf("partitionDevice(%q, %d) = %q, want %q", tc.disk, tc.part, got, tc.want)
		}
	}
}

func TestSgdiskArgs(t *testing.T) {
	o := Options{Disk: "/dev/nvme0n1", ESPLabel: "EFI", StateLabel: "cryptos-state", ESPSizeMiB: 512}
	args := strings.Join(sgdiskArgs(o), " ")
	for _, want := range []string{
		"--zap-all",
		"--new=1:0:+512MiB",
		"--typecode=1:" + espTypeGUID,
		"--change-name=1:EFI",
		"--new=2:0:0",
		"--typecode=2:" + stateTypeGUID,
		"--change-name=2:cryptos-state",
		"/dev/nvme0n1",
	} {
		if !strings.Contains(args, want) {
			t.Errorf("sgdisk args missing %q in: %s", want, args)
		}
	}
	// The disk must be the final argument.
	a := sgdiskArgs(o)
	if a[len(a)-1] != "/dev/nvme0n1" {
		t.Errorf("disk is not the last arg: %v", a)
	}
}

// TestInstall_SequenceAndCopy verifies the full happy-path for an sda disk:
// Runner sequence = sgdisk, mkfs.vfat (no partprobe, no /bin/mount, /bin/umount);
// Deps order = reread → waitForDevice → mount → unmount;
// mkfs targets the direct partition device (/dev/sda1, not by-partlabel);
// UKI is copied to the removable-media fallback path under mountDir.
func TestInstall_SequenceAndCopy(t *testing.T) {
	r := &mockRunner{}
	dr := &depsRecord{}

	var copiedDst, copiedSrc string
	copyFn := func(dst, src string) error { copiedDst, copiedSrc = dst, src; return nil }

	// mountDir must be writable: Install really creates EFI/BOOT under it.
	mnt := t.TempDir()

	err := Install(context.Background(),
		Options{Disk: "/dev/sda", UKI: "/build/out/cryptos.uki"},
		r, mnt, copyFn, dr.deps())
	if err != nil {
		t.Fatalf("Install: %v", err)
	}

	// Runner: only sgdisk and mkfs.vfat; no partprobe, no /bin/mount, no /bin/umount.
	wantCmds := []string{sgdiskBin, mkfsVfatBin}
	if strings.Join(r.names(), ",") != strings.Join(wantCmds, ",") {
		t.Errorf("Runner calls = %v, want %v", r.names(), wantCmds)
	}

	// mkfs.vfat target must be the direct device path, not by-partlabel.
	mkfs := r.calls[1]
	wantMkfsArgs := "-F 32 -n EFI /dev/sda1"
	if strings.Join(mkfs.args, " ") != wantMkfsArgs {
		t.Errorf("mkfs.vfat args = %q, want %q", strings.Join(mkfs.args, " "), wantMkfsArgs)
	}

	// Deps: reread called with disk, mount called with esp=sda1, unmount called once.
	if len(dr.rereadCalls) != 1 || dr.rereadCalls[0] != "/dev/sda" {
		t.Errorf("reread calls = %v, want [/dev/sda]", dr.rereadCalls)
	}
	if len(dr.mountCalls) != 1 || dr.mountCalls[0][0] != "/dev/sda1" {
		t.Errorf("mount calls = %v, want one call with esp=/dev/sda1", dr.mountCalls)
	}
	if len(dr.unmountCalls) != 1 {
		t.Errorf("unmount calls = %v, want 1", dr.unmountCalls)
	}

	// UKI copied to the removable-media fallback path.
	wantDst := filepath.Join(mnt, "EFI/BOOT/BOOTX64.EFI")
	if copiedSrc != "/build/out/cryptos.uki" || copiedDst != wantDst {
		t.Errorf("copy = %s -> %s, want /build/out/cryptos.uki -> %s", copiedSrc, copiedDst, wantDst)
	}
}

// TestInstall_NVMeDevice verifies the p-suffix partition naming for NVMe
// (name ends in a digit).
func TestInstall_NVMeDevice(t *testing.T) {
	r := &mockRunner{}
	dr := &depsRecord{}
	mnt := t.TempDir()

	err := Install(context.Background(),
		Options{Disk: "/dev/nvme0n1", UKI: "/build/out/cryptos.uki"},
		r, mnt, func(string, string) error { return nil }, dr.deps())
	if err != nil {
		t.Fatalf("Install (NVMe): %v", err)
	}

	// mkfs target must use p-suffix (/dev/nvme0n1p1).
	mkfs := r.calls[1]
	lastArg := mkfs.args[len(mkfs.args)-1]
	if lastArg != "/dev/nvme0n1p1" {
		t.Errorf("NVMe mkfs.vfat target = %q, want /dev/nvme0n1p1", lastArg)
	}
	if len(dr.mountCalls) != 1 || dr.mountCalls[0][0] != "/dev/nvme0n1p1" {
		t.Errorf("mount esp = %v, want /dev/nvme0n1p1", dr.mountCalls)
	}
}

// TestInstall_LoopDevice verifies the p-suffix partition naming for loop devices.
func TestInstall_LoopDevice(t *testing.T) {
	r := &mockRunner{}
	dr := &depsRecord{}
	mnt := t.TempDir()

	err := Install(context.Background(),
		Options{Disk: "/dev/loop0", UKI: "/build/out/cryptos.uki"},
		r, mnt, func(string, string) error { return nil }, dr.deps())
	if err != nil {
		t.Fatalf("Install (loop): %v", err)
	}

	mkfs := r.calls[1]
	lastArg := mkfs.args[len(mkfs.args)-1]
	if lastArg != "/dev/loop0p1" {
		t.Errorf("loop mkfs.vfat target = %q, want /dev/loop0p1", lastArg)
	}
}

func TestInstall_StopsOnError(t *testing.T) {
	r := &mockRunner{failOn: sgdiskBin}
	dr := &depsRecord{}
	copied := false
	err := Install(context.Background(),
		Options{Disk: "/dev/sda", UKI: "/x.uki"},
		r, "/mnt/esp", func(string, string) error { copied = true; return nil }, dr.deps())
	if err == nil {
		t.Fatal("Install should fail when sgdisk fails")
	}
	if copied {
		t.Error("UKI copied despite partitioning failure")
	}
	if len(r.calls) != 1 {
		t.Errorf("ran %d commands after sgdisk failure, want 1", len(r.calls))
	}
	// reread must NOT have been called (sgdisk failed before reaching it).
	if len(dr.rereadCalls) != 0 {
		t.Errorf("reread called after sgdisk failure; want 0 calls")
	}
}

func TestInstall_Validation(t *testing.T) {
	ok := func(string, string) error { return nil }
	dr := &depsRecord{}
	cases := []Options{
		{UKI: "/x.uki"},    // no disk
		{Disk: "/dev/sda"}, // no UKI
		{Disk: "/dev/sda", UKI: "/x", ESPSizeMiB: 1}, // ESP too small
	}
	for i, o := range cases {
		if err := Install(context.Background(), o, &mockRunner{}, "/mnt", ok, dr.deps()); err == nil {
			t.Errorf("case %d: expected validation error", i)
		}
	}
	// Missing Runner.
	if err := Install(context.Background(), Options{Disk: "/dev/sda", UKI: "/x"}, nil, "/mnt", ok, dr.deps()); err == nil {
		t.Error("nil runner should error")
	}
	// Empty Deps (nil functions).
	emptyDeps := Deps{}
	if err := Install(context.Background(), Options{Disk: "/dev/sda", UKI: "/x"}, &mockRunner{}, "/mnt", ok, emptyDeps); err == nil {
		t.Error("empty Deps should error")
	}
}

func TestStageConfig_WritesFile(t *testing.T) {
	esp := t.TempDir()
	raw := []byte("node: example\n")
	if err := StageConfig(esp, raw); err != nil {
		t.Fatalf("StageConfig: %v", err)
	}
	wantPath := filepath.Join(esp, "EFI/cryptos/machine.yaml")
	got, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatalf("reading staged config: %v", err)
	}
	if string(got) != string(raw) {
		t.Errorf("staged = %q, want %q", got, raw)
	}
}

func TestInstall_StagesConfig(t *testing.T) {
	r := &mockRunner{}
	dr := &depsRecord{}
	mnt := t.TempDir()
	cfg := []byte("node: staged\n")

	err := Install(context.Background(),
		Options{Disk: "/dev/sda", UKI: "/build/out/cryptos.uki", ConfigYAML: cfg},
		r, mnt, func(string, string) error { return nil }, dr.deps())
	if err != nil {
		t.Fatalf("Install with ConfigYAML: %v", err)
	}
	staged, err := os.ReadFile(filepath.Join(mnt, "EFI/cryptos/machine.yaml"))
	if err != nil {
		t.Fatalf("machine.yaml not staged: %v", err)
	}
	if string(staged) != string(cfg) {
		t.Errorf("staged = %q, want %q", staged, cfg)
	}
}

func TestInstall_SkipsConfigWhenEmpty(t *testing.T) {
	r := &mockRunner{}
	dr := &depsRecord{}
	mnt := t.TempDir()

	err := Install(context.Background(),
		Options{Disk: "/dev/sda", UKI: "/build/out/cryptos.uki"},
		r, mnt, func(string, string) error { return nil }, dr.deps())
	if err != nil {
		t.Fatalf("Install without ConfigYAML: %v", err)
	}
	if _, err := os.Stat(filepath.Join(mnt, "EFI/cryptos/machine.yaml")); !os.IsNotExist(err) {
		t.Error("machine.yaml should not exist when ConfigYAML is empty")
	}
}

// TestInstall_UnmountOnCopyError verifies that the ESP is unmounted even when
// the UKI copy fails.
func TestInstall_UnmountOnCopyError(t *testing.T) {
	r := &mockRunner{}
	dr := &depsRecord{}
	mnt := t.TempDir()

	copyErr := errors.New("disk full")
	err := Install(context.Background(),
		Options{Disk: "/dev/sda", UKI: "/x.uki"},
		r, mnt, func(string, string) error { return copyErr }, dr.deps())
	if err == nil {
		t.Fatal("expected error when copy fails")
	}
	if len(dr.unmountCalls) != 1 {
		t.Errorf("unmount calls = %d, want 1 (cleanup on error)", len(dr.unmountCalls))
	}
}
