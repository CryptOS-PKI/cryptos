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

func TestInstall_SequenceAndCopy(t *testing.T) {
	r := &mockRunner{}
	var copiedDst, copiedSrc string
	copyFn := func(dst, src string) error { copiedDst, copiedSrc = dst, src; return nil }

	// mountDir must be writable: Install really creates EFI/BOOT under it
	// (only the external commands are mocked).
	mnt := t.TempDir()
	err := Install(context.Background(),
		Options{Disk: "/dev/sda", UKI: "/build/out/cryptos.uki"},
		r, mnt, copyFn)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}

	want := []string{sgdiskBin, partprobeBin, mkfsVfatBin, mountBin, umountBin}
	if strings.Join(r.names(), ",") != strings.Join(want, ",") {
		t.Errorf("call sequence = %v, want %v", r.names(), want)
	}
	// Defaults applied: ESP label EFI, state label cryptos-state.
	mkfs := r.calls[2]
	if strings.Join(mkfs.args, " ") != "-F 32 -n EFI /dev/disk/by-partlabel/EFI" {
		t.Errorf("mkfs.vfat args = %v", mkfs.args)
	}
	// UKI copied to the removable-media fallback path under the mount.
	wantDst := filepath.Join(mnt, "EFI/BOOT/BOOTX64.EFI")
	if copiedSrc != "/build/out/cryptos.uki" || copiedDst != wantDst {
		t.Errorf("copy = %s -> %s, want /build/out/cryptos.uki -> %s", copiedSrc, copiedDst, wantDst)
	}
}

func TestInstall_StopsOnError(t *testing.T) {
	r := &mockRunner{failOn: sgdiskBin}
	copied := false
	err := Install(context.Background(),
		Options{Disk: "/dev/sda", UKI: "/x.uki"},
		r, "/mnt/esp", func(string, string) error { copied = true; return nil })
	if err == nil {
		t.Fatal("Install should fail when sgdisk fails")
	}
	if copied {
		t.Error("UKI copied despite partitioning failure")
	}
	if len(r.calls) != 1 {
		t.Errorf("ran %d commands after sgdisk failure, want 1", len(r.calls))
	}
}

func TestInstall_Validation(t *testing.T) {
	ok := func(string, string) error { return nil }
	cases := []Options{
		{UKI: "/x.uki"},    // no disk
		{Disk: "/dev/sda"}, // no UKI
		{Disk: "/dev/sda", UKI: "/x", ESPSizeMiB: 1}, // ESP too small
	}
	for i, o := range cases {
		if err := Install(context.Background(), o, &mockRunner{}, "/mnt", ok); err == nil {
			t.Errorf("case %d: expected validation error", i)
		}
	}
	// Missing collaborators.
	if err := Install(context.Background(), Options{Disk: "/dev/sda", UKI: "/x"}, nil, "/mnt", ok); err == nil {
		t.Error("nil runner should error")
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
	mnt := t.TempDir()
	cfg := []byte("node: staged\n")
	err := Install(context.Background(),
		Options{Disk: "/dev/sda", UKI: "/build/out/cryptos.uki", ConfigYAML: cfg},
		r, mnt, func(string, string) error { return nil })
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
	mnt := t.TempDir()
	err := Install(context.Background(),
		Options{Disk: "/dev/sda", UKI: "/build/out/cryptos.uki"},
		r, mnt, func(string, string) error { return nil })
	if err != nil {
		t.Fatalf("Install without ConfigYAML: %v", err)
	}
	if _, err := os.Stat(filepath.Join(mnt, "EFI/cryptos/machine.yaml")); !os.IsNotExist(err) {
		t.Error("machine.yaml should not exist when ConfigYAML is empty")
	}
}
