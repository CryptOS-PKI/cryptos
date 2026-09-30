package main

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
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// newStdinCmd returns a command wired with the given stdin and a captured
// stdout, for exercising the escrow prompts and gate directly.
func newStdinCmd(stdin string) (*cobra.Command, *bytes.Buffer) {
	cmd := &cobra.Command{}
	out := &bytes.Buffer{}
	cmd.SetOut(out)
	cmd.SetIn(strings.NewReader(stdin))
	return cmd, out
}

func TestExportImportRegisteredUnderCA(t *testing.T) {
	ca := newCACmd(&globalOpts{})
	want := map[string]bool{"export-key": false, "import-key": false}
	for _, sub := range ca.Commands() {
		if _, ok := want[sub.Name()]; ok {
			want[sub.Name()] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("%q not registered under ca", name)
		}
	}
}

func TestExportKeyRequiresOut(t *testing.T) {
	if _, err := runCmd(t, "ca", "export-key"); err == nil {
		t.Error("export-key without --out = nil, want error")
	}
}

func TestImportKeyRequiresBackup(t *testing.T) {
	if _, err := runCmd(t, "ca", "import-key"); err == nil {
		t.Error("import-key without --backup = nil, want error")
	}
}

func TestConfirmExport_Root(t *testing.T) {
	// Correct CN proceeds.
	cmd, _ := newStdinCmd("ACME Root CA G1\n")
	if err := confirmExport(cmd, "ACME Root CA G1", true, false); err != nil {
		t.Fatalf("root with correct CN should proceed, got %v", err)
	}
	// Wrong CN and a plain "yes" both abort on a root.
	for _, in := range []string{"wrong\n", "yes\n"} {
		cmd, _ := newStdinCmd(in)
		if err := confirmExport(cmd, "ACME Root CA G1", true, false); err == nil {
			t.Fatalf("root with input %q should abort", in)
		}
	}
	// --yes skips the prompt.
	cmd, _ = newStdinCmd("")
	if err := confirmExport(cmd, "ACME Root CA G1", true, true); err != nil {
		t.Fatalf("--yes should skip confirmation, got %v", err)
	}
}

func TestConfirmExport_Subordinate(t *testing.T) {
	cmd, _ := newStdinCmd("yes\n")
	if err := confirmExport(cmd, "", false, false); err != nil {
		t.Fatalf("subordinate with yes should proceed, got %v", err)
	}
	cmd, _ = newStdinCmd("no\n")
	if err := confirmExport(cmd, "", false, false); err == nil {
		t.Fatal("subordinate with 'no' should abort")
	}
}

func TestPromptNewPassphrase(t *testing.T) {
	cmd, _ := newStdinCmd("s3cret\ns3cret\n")
	pass, err := promptNewPassphrase(cmd)
	if err != nil {
		t.Fatalf("matching passphrases should succeed, got %v", err)
	}
	if string(pass) != "s3cret" {
		t.Errorf("passphrase = %q, want s3cret", pass)
	}

	cmd, _ = newStdinCmd("one\ntwo\n")
	if _, err := promptNewPassphrase(cmd); err == nil {
		t.Fatal("mismatched passphrases should error")
	}

	cmd, _ = newStdinCmd("\n\n")
	if _, err := promptNewPassphrase(cmd); err == nil {
		t.Fatal("empty passphrase should error")
	}
}
