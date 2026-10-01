package audit

/*
Copyright The CryptOS Authors.

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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
)

// DefaultPageSize is the page size List uses when the query leaves it unset.
const DefaultPageSize = 100

// MaxPageSize caps a query's page size; a larger request is clamped to it.
const MaxPageSize = 1000

// Query selects audit entries for List. Every set filter must match.
type Query struct {
	// Since keeps entries stamped at or after it; zero means no lower bound.
	Since time.Time
	// Until keeps entries stamped before it; zero means no upper bound.
	Until time.Time
	// Method keeps entries whose rpc_method equals it, either the full
	// gRPC name ("/cryptos.node.v1.NodeService/IssueLeaf", the leading slash
	// optional) or the method name alone ("IssueLeaf"). Case-sensitive.
	Method string
	// Actor keeps entries whose actor_subject contains it. Case-sensitive.
	Actor string
	// PageSize is the most entries to return: DefaultPageSize when zero or
	// negative, clamped to MaxPageSize.
	PageSize int
	// AfterSeq resumes a listing after this sequence number, taken from the
	// previous page's NextAfterSeq; zero starts at the first entry.
	AfterSeq uint64
}

// Entry is one stored audit entry.
type Entry struct {
	// Event is the entry as stored, signed and chained.
	Event *nodev1.AuditEvent
	// SHA256 is the hash of the entry's bytes on disk: the value the next
	// entry's prev_entry_sha256 holds. Re-encoding Event would not
	// reproduce those bytes, so it is taken on read.
	SHA256 [32]byte
}

// Page is one page of List results, in sequence order.
type Page struct {
	Entries []Entry
	// NextAfterSeq is the AfterSeq for the next page, or zero when no
	// further entry matches the query.
	NextAfterSeq uint64
}

// VerifyResult is the outcome of verifying the whole stored chain.
type VerifyResult struct {
	// Entries is the number of entries (lines) in the log, counted past a
	// break.
	Entries uint64
	// Intact is true when every entry verified.
	Intact bool
	// FirstBrokenSeq is the sequence number at which the chain first fails
	// to verify: the seq the failing entry holds, or the one expected at
	// its position when the entry can't be read. Zero when Intact.
	FirstBrokenSeq uint64
	// Reason says why the chain broke, naming the file and line. Empty
	// when Intact.
	Reason string
}

// List returns the page of stored entries that match q, oldest first. Lines
// that don't parse are skipped here; Verify reports them. It holds the
// append lock while it reads, so a page never includes a half-written line.
func (l *Logger) List(q Query) (Page, error) {
	size := q.PageSize
	if size <= 0 {
		size = DefaultPageSize
	}
	if size > MaxPageSize {
		size = MaxPageSize
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	var page Page
	err := walkLines(l.dir, func(_ string, _ int, line string) (bool, error) {
		jsonBytes, _, ok := splitLine(line)
		if !ok {
			return true, nil
		}
		ev := &nodev1.AuditEvent{}
		if err := protojson.Unmarshal(jsonBytes, ev); err != nil {
			return true, nil
		}
		if ev.GetSeq() <= q.AfterSeq || !q.matches(ev) {
			return true, nil
		}
		if len(page.Entries) == size {
			page.NextAfterSeq = page.Entries[size-1].Event.GetSeq()
			return false, nil
		}
		page.Entries = append(page.Entries, Entry{Event: ev, SHA256: sha256.Sum256(jsonBytes)})
		return true, nil
	})
	if err != nil {
		return Page{}, fmt.Errorf("audit: List: %w", err)
	}
	return page, nil
}

func (q Query) matches(ev *nodev1.AuditEvent) bool {
	if q.Method != "" {
		m := ev.GetRpcMethod()
		if strings.TrimPrefix(m, "/") != strings.TrimPrefix(q.Method, "/") && MethodName(m) != q.Method {
			return false
		}
	}
	if q.Actor != "" && !strings.Contains(ev.GetActorSubject(), q.Actor) {
		return false
	}
	if !q.Since.IsZero() || !q.Until.IsZero() {
		ts := ev.GetTs().AsTime()
		if !q.Since.IsZero() && ts.Before(q.Since) {
			return false
		}
		if !q.Until.IsZero() && !ts.Before(q.Until) {
			return false
		}
	}
	return true
}

// Verify checks the whole stored chain against this logger's public key,
// under the append lock. A broken chain is a result, not an error; the error
// is for a log that can't be read.
func (l *Logger) Verify() (VerifyResult, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return verifyDir(l.dir, l.PublicKey())
}

// verifyDir walks every log file in dir in date order and checks each line
// is well-formed, carries a valid signature, holds the next sequence number,
// and chains to the SHA-256 of the prior entry (SHA-256 of empty bytes for
// the first). It records the first failure and keeps counting entries.
func verifyDir(dir string, pubKey ed25519.PublicKey) (VerifyResult, error) {
	res := VerifyResult{Intact: true}
	prev := sha256.Sum256(nil)
	expectedSeq := uint64(1)
	broken := func(seq uint64, name string, lineNo int, format string, args ...any) {
		res.Intact = false
		res.FirstBrokenSeq = seq
		res.Reason = fmt.Sprintf("%s:%d: ", name, lineNo) + fmt.Sprintf(format, args...)
	}
	err := walkLines(dir, func(name string, lineNo int, line string) (bool, error) {
		res.Entries++
		if !res.Intact {
			return true, nil
		}
		jsonBytes, sig, ok := splitLine(line)
		if !ok {
			broken(expectedSeq, name, lineNo, "malformed line")
			return true, nil
		}
		var event nodev1.AuditEvent
		if err := protojson.Unmarshal(jsonBytes, &event); err != nil {
			broken(expectedSeq, name, lineNo, "protojson: %v", err)
			return true, nil
		}
		if !ed25519.Verify(pubKey, jsonBytes, sig) {
			broken(event.Seq, name, lineNo, "signature mismatch")
			return true, nil
		}
		if event.Seq != expectedSeq {
			broken(event.Seq, name, lineNo, "seq=%d want %d", event.Seq, expectedSeq)
			return true, nil
		}
		if !bytesEqual(event.PrevEntrySha256, prev[:]) {
			broken(event.Seq, name, lineNo, "prev_entry_sha256 mismatch")
			return true, nil
		}
		prev = sha256.Sum256(jsonBytes)
		expectedSeq++
		return true, nil
	})
	if err != nil {
		return VerifyResult{}, err
	}
	return res, nil
}

// walkLines calls fn for each line of each log file in dir, in date order,
// until fn returns false or an error.
func walkLines(dir string, fn func(name string, lineNo int, line string) (bool, error)) error {
	files, err := listLogFiles(dir)
	if err != nil {
		return err
	}
	for _, name := range files {
		more, err := walkFile(filepath.Join(dir, name), name, fn)
		if err != nil {
			return err
		}
		if !more {
			return nil
		}
	}
	return nil
}

func walkFile(path, name string, fn func(name string, lineNo int, line string) (bool, error)) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		more, err := fn(name, lineNo, scanner.Text())
		if err != nil || !more {
			return more, err
		}
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("scan %s: %w", path, err)
	}
	return true, nil
}
