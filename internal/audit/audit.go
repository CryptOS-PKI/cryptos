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
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
)

// AuditSignerLabel is the HKDF info parameter for deriving the Ed25519
// audit-signing key. Stable across the project lifetime; bumping the
// version suffix would invalidate all prior signatures.
const AuditSignerLabel = "cryptos.dev/audit-signer/v1"

// SeedLength is the required length of the master audit seed passed to
// Open. The seed is high-entropy bytes generated at first-boot ceremony
// and persisted on the encrypted state partition.
const SeedLength = 32

// Logger appends signed, hash-chained AuditEvents to a directory of
// per-UTC-day log files. Safe for concurrent use across goroutines.
//
// Disk format: one event per line, formatted as
//
//	<protojson(AuditEvent)> <single space> <base64-no-padding ed25519 signature>
//
// The signature covers the protojson bytes exactly as written (before
// newline). Each event's prev_entry_sha256 is the SHA-256 of the prior
// event's protojson bytes; the very first entry uses the SHA-256 of an
// empty byte slice.
type Logger struct {
	mu sync.Mutex

	dir    string
	signer ed25519.PrivateKey
	now    func() time.Time // injectable for tests

	curFile    *os.File
	curDate    string // YYYY-MM-DD of the currently-open file
	nextSeq    uint64
	prevSHA256 [32]byte
}

// Open returns a Logger writing into dir. seed must be exactly
// SeedLength bytes. If dir contains existing log files, the logger
// scans the most recent file to restore the running sequence number
// and the prior entry's hash so the chain continues seamlessly.
func Open(dir string, seed []byte) (*Logger, error) {
	if dir == "" {
		return nil, errors.New("audit: Open: dir is required")
	}
	if len(seed) != SeedLength {
		return nil, fmt.Errorf("audit: Open: seed must be %d bytes, got %d", SeedLength, len(seed))
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("audit: Open: MkdirAll: %w", err)
	}
	signer, err := deriveSigner(seed)
	if err != nil {
		return nil, err
	}
	l := &Logger{
		dir:    dir,
		signer: signer,
		now:    time.Now,
	}
	if err := l.restoreState(); err != nil {
		return nil, err
	}
	return l, nil
}

// deriveSigner returns the Ed25519 private key derived via HKDF-SHA256
// from seed with the project label.
func deriveSigner(seed []byte) (ed25519.PrivateKey, error) {
	r := hkdf.New(sha256.New, seed, nil, []byte(AuditSignerLabel))
	out := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, fmt.Errorf("audit: deriveSigner: HKDF read: %w", err)
	}
	return ed25519.NewKeyFromSeed(out), nil
}

// PublicKey returns the audit log's verifying public key. Operators
// distribute this so external verifiers can run VerifyChain offline.
func (l *Logger) PublicKey() ed25519.PublicKey {
	if l == nil || l.signer == nil {
		return nil
	}
	return l.signer.Public().(ed25519.PublicKey)
}

// restoreState scans the directory and seeds nextSeq / prevSHA256 from
// the latest log file. An empty directory starts at seq 1 and the
// canonical "empty input" SHA-256.
func (l *Logger) restoreState() error {
	files, err := listLogFiles(l.dir)
	if err != nil {
		return err
	}
	l.prevSHA256 = sha256.Sum256(nil)
	l.nextSeq = 1
	if len(files) == 0 {
		return nil
	}
	last := files[len(files)-1]
	lastSeq, lastBytes, err := scanLastEntry(filepath.Join(l.dir, last))
	if err != nil {
		return fmt.Errorf("audit: restoreState: scan %s: %w", last, err)
	}
	if lastSeq > 0 {
		l.nextSeq = lastSeq + 1
		l.prevSHA256 = sha256.Sum256(lastBytes)
	}
	return nil
}

// Append signs and writes event. The caller leaves seq and
// prev_entry_sha256 unset; Append fills them in and signs the result.
// The supplied event is not modified.
func (l *Logger) Append(event *cryptosv1.AuditEvent) error {
	if l == nil {
		return errors.New("audit: Append: nil logger")
	}
	if event == nil {
		return errors.New("audit: Append: nil event")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.rotateIfNeeded(); err != nil {
		return err
	}
	now := l.now()
	full := proto.Clone(event).(*cryptosv1.AuditEvent)
	full.Seq = l.nextSeq
	if full.Ts == nil {
		full.Ts = timestamppb.New(now)
	}
	full.PrevEntrySha256 = append([]byte(nil), l.prevSHA256[:]...)

	jsonBytes, err := protojson.Marshal(full)
	if err != nil {
		return fmt.Errorf("audit: Append: protojson.Marshal: %w", err)
	}
	sig := ed25519.Sign(l.signer, jsonBytes)
	line := append([]byte{}, jsonBytes...)
	line = append(line, ' ')
	line = append(line, []byte(base64.RawStdEncoding.EncodeToString(sig))...)
	line = append(line, '\n')
	if _, err := l.curFile.Write(line); err != nil {
		return fmt.Errorf("audit: Append: write: %w", err)
	}
	if err := l.curFile.Sync(); err != nil {
		return fmt.Errorf("audit: Append: sync: %w", err)
	}
	l.nextSeq++
	l.prevSHA256 = sha256.Sum256(jsonBytes)
	return nil
}

// rotateIfNeeded opens (or reopens) the file for the current UTC date,
// closing the prior one if the date has changed.
func (l *Logger) rotateIfNeeded() error {
	date := l.now().UTC().Format("2006-01-02")
	if date == l.curDate && l.curFile != nil {
		return nil
	}
	if l.curFile != nil {
		_ = l.curFile.Close()
		l.curFile = nil
	}
	path := filepath.Join(l.dir, date+".log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("audit: rotate: open %s: %w", path, err)
	}
	l.curFile = f
	l.curDate = date
	return nil
}

// Close flushes and closes the current file. Safe to call multiple times.
func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.curFile == nil {
		return nil
	}
	err := l.curFile.Close()
	l.curFile = nil
	if err != nil {
		return fmt.Errorf("audit: Close: %w", err)
	}
	return nil
}

// VerifyChain walks every log file in dir in date order and verifies:
//
//   - each line is well-formed (event JSON + signature),
//   - each signature matches pubKey,
//   - the sequence numbers are strictly increasing without gaps,
//   - each entry's prev_entry_sha256 matches the SHA-256 of the prior
//     entry's protojson bytes (or SHA-256 of empty bytes for the very
//     first entry across all files).
//
// On error VerifyChain returns the first inconsistency it finds with
// enough context to identify the offending file + line.
func VerifyChain(dir string, pubKey ed25519.PublicKey) error {
	files, err := listLogFiles(dir)
	if err != nil {
		return err
	}
	prev := sha256.Sum256(nil)
	expectedSeq := uint64(1)
	for _, name := range files {
		path := filepath.Join(dir, name)
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("audit: VerifyChain: open %s: %w", path, err)
		}
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		lineNo := 0
		for scanner.Scan() {
			lineNo++
			line := scanner.Text()
			jsonBytes, sig, ok := splitLine(line)
			if !ok {
				_ = f.Close()
				return fmt.Errorf("audit: VerifyChain: %s:%d: malformed line", name, lineNo)
			}
			if !ed25519.Verify(pubKey, jsonBytes, sig) {
				_ = f.Close()
				return fmt.Errorf("audit: VerifyChain: %s:%d: signature mismatch", name, lineNo)
			}
			var event cryptosv1.AuditEvent
			if err := protojson.Unmarshal(jsonBytes, &event); err != nil {
				_ = f.Close()
				return fmt.Errorf("audit: VerifyChain: %s:%d: protojson: %w", name, lineNo, err)
			}
			if event.Seq != expectedSeq {
				_ = f.Close()
				return fmt.Errorf("audit: VerifyChain: %s:%d: seq=%d want %d", name, lineNo, event.Seq, expectedSeq)
			}
			if !bytesEqual(event.PrevEntrySha256, prev[:]) {
				_ = f.Close()
				return fmt.Errorf("audit: VerifyChain: %s:%d: prev_entry_sha256 mismatch", name, lineNo)
			}
			prev = sha256.Sum256(jsonBytes)
			expectedSeq++
		}
		if err := scanner.Err(); err != nil {
			_ = f.Close()
			return fmt.Errorf("audit: VerifyChain: scan %s: %w", path, err)
		}
		_ = f.Close()
	}
	return nil
}

// listLogFiles returns *.log filenames in dir in lexical (date) order.
func listLogFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("audit: list %s: %w", dir, err)
	}
	var names []string
	for _, e := range entries {
		n := e.Name()
		if !e.IsDir() && strings.HasSuffix(n, ".log") {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names, nil
}

// scanLastEntry reads path line-by-line and returns the seq + raw
// protojson bytes of the last well-formed entry. Returns (0, nil, nil)
// for an empty file.
func scanLastEntry(path string) (uint64, []byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var lastSeq uint64
	var lastBytes []byte
	for scanner.Scan() {
		line := scanner.Text()
		jsonBytes, _, ok := splitLine(line)
		if !ok {
			continue
		}
		var ev cryptosv1.AuditEvent
		if err := protojson.Unmarshal(jsonBytes, &ev); err != nil {
			continue
		}
		lastSeq = ev.Seq
		lastBytes = append(lastBytes[:0], jsonBytes...)
	}
	if err := scanner.Err(); err != nil {
		return 0, nil, err
	}
	return lastSeq, lastBytes, nil
}

// splitLine splits an audit log line into (jsonBytes, signatureBytes).
// Format: "<json> <base64-no-padding signature>".
func splitLine(line string) (jsonBytes []byte, sig []byte, ok bool) {
	idx := strings.LastIndexByte(line, ' ')
	if idx <= 0 || idx == len(line)-1 {
		return nil, nil, false
	}
	sig, err := base64.RawStdEncoding.DecodeString(line[idx+1:])
	if err != nil {
		return nil, nil, false
	}
	return []byte(line[:idx]), sig, true
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
