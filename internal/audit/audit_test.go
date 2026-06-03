package audit

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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
)

func mustSeed(t *testing.T) []byte {
	t.Helper()
	s := make([]byte, SeedLength)
	if _, err := rand.Read(s); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return s
}

func newEvent(method string) *cryptosv1.AuditEvent {
	digest := sha256.Sum256([]byte(method))
	return &cryptosv1.AuditEvent{
		ActorSubject:        "CN=test-admin",
		RpcMethod:           method,
		RequestDigestSha256: digest[:],
		Outcome:             cryptosv1.Outcome_OUTCOME_OK,
	}
}

func TestAppend_AndVerifyChain(t *testing.T) {
	dir := t.TempDir()
	seed := mustSeed(t)

	logger, err := Open(dir, seed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	pub := logger.PublicKey()

	for i := 0; i < 5; i++ {
		if err := logger.Append(newEvent("cryptos.v1.NodeService/GetStatus")); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	if err := logger.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := VerifyChain(dir, pub); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
}

func TestVerifyChain_DetectsSignatureTamper(t *testing.T) {
	dir := t.TempDir()
	seed := mustSeed(t)
	logger, err := Open(dir, seed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	pub := logger.PublicKey()
	if err := logger.Append(newEvent("a")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := logger.Append(newEvent("b")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := logger.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Flip a byte in the signature of the last line of the only file.
	files, _ := os.ReadDir(dir)
	path := filepath.Join(dir, files[0].Name())
	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	last := lines[len(lines)-1]
	idx := strings.LastIndexByte(last, ' ')
	if idx <= 0 {
		t.Fatalf("malformed line: %q", last)
	}
	sigB64 := last[idx+1:]
	sig, _ := base64.RawStdEncoding.DecodeString(sigB64)
	sig[0] ^= 0x01 // flip a bit
	lines[len(lines)-1] = last[:idx+1] + base64.RawStdEncoding.EncodeToString(sig)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write tampered: %v", err)
	}

	if err := VerifyChain(dir, pub); err == nil {
		t.Fatalf("VerifyChain should have failed after sig tamper")
	}
}

func TestVerifyChain_DetectsChainBreak(t *testing.T) {
	dir := t.TempDir()
	seed := mustSeed(t)
	logger, err := Open(dir, seed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	pub := logger.PublicKey()
	for i := 0; i < 3; i++ {
		if err := logger.Append(newEvent("e")); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	if err := logger.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Drop the middle line: the chain hash on the third line will no
	// longer match the SHA-256 of the new second line.
	files, _ := os.ReadDir(dir)
	path := filepath.Join(dir, files[0].Name())
	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	kept := append(lines[:1], lines[2:]...)
	if err := os.WriteFile(path, []byte(strings.Join(kept, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write tampered: %v", err)
	}

	if err := VerifyChain(dir, pub); err == nil {
		t.Fatalf("VerifyChain should detect a chain break")
	}
}

func TestVerifyChain_WrongPubKeyFails(t *testing.T) {
	dir := t.TempDir()
	seed := mustSeed(t)
	logger, err := Open(dir, seed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := logger.Append(newEvent("e")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := logger.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := VerifyChain(dir, otherPub); err == nil {
		t.Fatalf("VerifyChain should fail with the wrong public key")
	}
}

func TestOpen_RestoresStateAfterReopen(t *testing.T) {
	dir := t.TempDir()
	seed := mustSeed(t)

	logger, err := Open(dir, seed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	pub := logger.PublicKey()
	for i := 0; i < 3; i++ {
		if err := logger.Append(newEvent("a")); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	if err := logger.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopen and continue.
	logger2, err := Open(dir, seed)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if !ed25519.PublicKey(pub).Equal(logger2.PublicKey()) {
		t.Fatalf("public key differs after reopen")
	}
	for i := 0; i < 3; i++ {
		if err := logger2.Append(newEvent("b")); err != nil {
			t.Fatalf("Append after reopen: %v", err)
		}
	}
	if err := logger2.Close(); err != nil {
		t.Fatalf("Close after reopen: %v", err)
	}

	// Whole chain (6 events across one or two files) must verify.
	if err := VerifyChain(dir, pub); err != nil {
		t.Fatalf("VerifyChain after reopen: %v", err)
	}
}

func TestAppend_DayRollover(t *testing.T) {
	dir := t.TempDir()
	seed := mustSeed(t)
	logger, err := Open(dir, seed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	pub := logger.PublicKey()

	// Pin time to day 1 for the first batch.
	day1 := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	logger.now = func() time.Time { return day1 }
	for i := 0; i < 2; i++ {
		if err := logger.Append(newEvent("d1")); err != nil {
			t.Fatalf("Append day 1: %v", err)
		}
	}

	// Advance to day 2.
	day2 := day1.Add(24 * time.Hour)
	logger.now = func() time.Time { return day2 }
	for i := 0; i < 2; i++ {
		if err := logger.Append(newEvent("d2")); err != nil {
			t.Fatalf("Append day 2: %v", err)
		}
	}

	if err := logger.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	files, _ := os.ReadDir(dir)
	if len(files) != 2 {
		t.Fatalf("expected 2 log files (one per day), got %d", len(files))
	}
	if err := VerifyChain(dir, pub); err != nil {
		t.Fatalf("VerifyChain across days: %v", err)
	}
}

func TestOpen_RejectsBadSeed(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(dir, nil); err == nil {
		t.Fatalf("Open(nil seed) should fail")
	}
	if _, err := Open(dir, make([]byte, SeedLength-1)); err == nil {
		t.Fatalf("Open(short seed) should fail")
	}
	if _, err := Open("", mustSeed(t)); err == nil {
		t.Fatalf("Open(empty dir) should fail")
	}
}

func TestAppend_FillsSeqAndPrevHash(t *testing.T) {
	dir := t.TempDir()
	logger, err := Open(dir, mustSeed(t))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = logger.Close() }()
	in := newEvent("x")
	if err := logger.Append(in); err != nil {
		t.Fatalf("Append: %v", err)
	}
	// The caller's event must NOT be mutated.
	if in.Seq != 0 || in.PrevEntrySha256 != nil {
		t.Fatalf("Append mutated caller's event: seq=%d prev=%v", in.Seq, in.PrevEntrySha256)
	}
}
