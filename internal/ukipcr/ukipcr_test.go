package ukipcr

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
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

type section struct {
	name string
	data []byte
	// vsize overrides VirtualSize; zero means len(data).
	vsize uint32
}

// buildPE writes a minimal PE32+ image with the given sections, in the given
// table order. Raw data is padded to 512 bytes, the way a linker (and ukify)
// pads to FileAlignment, so VirtualSize and SizeOfRawData differ as in a real
// UKI.
func buildPE(t *testing.T, sections ...section) []byte {
	t.Helper()
	const (
		peOffset   = 0x40
		optSize    = 240
		headerSize = peOffset + 4 + 20 + optSize
		align      = 512
	)
	var b bytes.Buffer
	dos := make([]byte, peOffset)
	copy(dos, "MZ")
	binary.LittleEndian.PutUint32(dos[0x3c:], peOffset)
	b.Write(dos)
	b.WriteString("PE\x00\x00")

	coff := make([]byte, 20)
	binary.LittleEndian.PutUint16(coff[0:], 0x8664)
	binary.LittleEndian.PutUint16(coff[2:], uint16(len(sections)))
	binary.LittleEndian.PutUint16(coff[16:], optSize)
	binary.LittleEndian.PutUint16(coff[18:], 0x22)
	b.Write(coff)

	opt := make([]byte, optSize)
	binary.LittleEndian.PutUint16(opt[0:], 0x20b)
	binary.LittleEndian.PutUint32(opt[108:], 16)
	b.Write(opt)

	dataStart := headerSize + 40*len(sections)
	dataStart = (dataStart + align - 1) / align * align
	var data bytes.Buffer
	for i, s := range sections {
		raw := len(s.data)
		if raw%align != 0 {
			raw += align - raw%align
		}
		vsize := s.vsize
		if vsize == 0 {
			vsize = uint32(len(s.data))
		}
		hdr := make([]byte, 40)
		copy(hdr[0:8], s.name)
		binary.LittleEndian.PutUint32(hdr[8:], vsize)
		binary.LittleEndian.PutUint32(hdr[12:], uint32(0x1000*(i+1)))
		binary.LittleEndian.PutUint32(hdr[16:], uint32(raw))
		binary.LittleEndian.PutUint32(hdr[20:], uint32(dataStart+data.Len()))
		b.Write(hdr)
		data.Write(s.data)
		data.Write(make([]byte, raw-len(s.data)))
	}
	b.Write(make([]byte, dataStart-b.Len()))
	b.Write(data.Bytes())

	return b.Bytes()
}

// reference folds the stub's measurement by hand for the named sections, in
// the order given, over the exact bytes given.
func reference(events ...[]byte) []byte {
	pcr := make([]byte, sha256.Size)
	for _, e := range events {
		d := sha256.Sum256(e)
		h := sha256.New()
		h.Write(pcr)
		h.Write(d[:])
		pcr = h.Sum(nil)
	}

	return pcr
}

func uki(t *testing.T) []byte {
	t.Helper()

	return buildPE(t,
		section{name: ".text", data: []byte("stub code")},
		section{name: ".sdmagic", data: []byte("#### LoaderInfo: systemd-stub 256 ####")},
		// Deliberately out of the stub's order: measurement order is fixed.
		section{name: ".initrd", data: []byte("initrd bytes")},
		section{name: ".linux", data: []byte("kernel bytes")},
		section{name: ".cmdline", data: []byte("console=ttyS0")},
		section{name: ".osrel", data: []byte("ID=cryptos\n")},
		section{name: ".sbat", data: []byte("sbat,1\n")},
		section{name: ".reloc", data: []byte{0, 0}},
	)
}

func TestPredict_FollowsTheStubOrderNotTheFileOrder(t *testing.T) {
	got, err := Predict(uki(t))
	if err != nil {
		t.Fatalf("Predict: %v", err)
	}

	want := reference(
		[]byte(".linux\x00"), []byte("kernel bytes"),
		[]byte(".osrel\x00"), []byte("ID=cryptos\n"),
		[]byte(".cmdline\x00"), []byte("console=ttyS0"),
		[]byte(".initrd\x00"), []byte("initrd bytes"),
		[]byte(".sbat\x00"), []byte("sbat,1\n"),
	)
	if !bytes.Equal(got.Value, want) {
		t.Errorf("Predict = %x, want %x", got.Value, want)
	}
	if strings.Join(got.Sections, ",") != ".linux,.osrel,.cmdline,.initrd,.sbat" {
		t.Errorf("Sections = %v", got.Sections)
	}
}

// A fixed answer, so a change to the algorithm cannot slip past both the code
// and the hand-written reference above at once.
func TestPredict_KnownAnswer(t *testing.T) {
	got, err := Predict(uki(t))
	if err != nil {
		t.Fatalf("Predict: %v", err)
	}
	const want = "da1a5450462272ac3b92fc0a86825c576c1843c6f11c3421d92beeba83e85861"
	if hex.EncodeToString(got.Value) != want {
		t.Errorf("Predict = %x, want %s", got.Value, want)
	}
}

func TestPredict_MeasuresVirtualSizeBytes(t *testing.T) {
	// Shorter than the raw data: the padding is not measured.
	short, err := Predict(buildPE(t, section{name: ".linux", data: []byte("kernel-and-trailing"), vsize: 6}))
	if err != nil {
		t.Fatalf("Predict: %v", err)
	}
	if want := reference([]byte(".linux\x00"), []byte("kernel")); !bytes.Equal(short.Value, want) {
		t.Errorf("truncated section: got %x, want %x", short.Value, want)
	}

	// Longer than the raw data: the rest is zero-filled, as in memory.
	long, err := Predict(buildPE(t, section{name: ".linux", data: []byte("k"), vsize: 600}))
	if err != nil {
		t.Fatalf("Predict: %v", err)
	}
	padded := append([]byte("k"), make([]byte, 599)...)
	if want := reference([]byte(".linux\x00"), padded); !bytes.Equal(long.Value, want) {
		t.Errorf("zero-filled section: got %x, want %x", long.Value, want)
	}
}

func TestPredict_SkipsThePCRSignature(t *testing.T) {
	with, err := Predict(buildPE(t,
		section{name: ".linux", data: []byte("k")},
		section{name: ".pcrsig", data: []byte(`{"sha256":[]}`)},
	))
	if err != nil {
		t.Fatalf("Predict: %v", err)
	}
	without, err := Predict(buildPE(t, section{name: ".linux", data: []byte("k")}))
	if err != nil {
		t.Fatalf("Predict: %v", err)
	}
	if !bytes.Equal(with.Value, without.Value) {
		t.Error(".pcrsig changed the prediction")
	}
}

func TestPredict_ChangesWithTheImage(t *testing.T) {
	a, err := Predict(buildPE(t, section{name: ".linux", data: []byte("v1")}))
	if err != nil {
		t.Fatalf("Predict: %v", err)
	}
	b, err := Predict(buildPE(t, section{name: ".linux", data: []byte("v2")}))
	if err != nil {
		t.Fatalf("Predict: %v", err)
	}
	if bytes.Equal(a.Value, b.Value) {
		t.Error("two different kernels predicted the same PCR 11")
	}
}

func TestPredict_RefusesWhatItCannotBeSureOf(t *testing.T) {
	k := section{name: ".linux", data: []byte("k")}
	for name, image := range map[string][]byte{
		"not a PE":         []byte("definitely not a PE file"),
		"no kernel":        buildPE(t, section{name: ".osrel", data: []byte("ID=x")}),
		"unknown section":  buildPE(t, k, section{name: ".mystery", data: []byte("?")}),
		"prefix match":     buildPE(t, k, section{name: ".dtbauto", data: []byte("dtb")}),
		"repeated section": buildPE(t, k, section{name: ".linux", data: []byte("again")}),
		"multi-profile":    buildPE(t, k, section{name: ".profile", data: []byte("ID=a")}),
		"oversized":        buildPE(t, section{name: ".linux", data: []byte("k"), vsize: 1 << 30}),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Predict(image)
			if !errors.Is(err, ErrUnpredictable) {
				t.Fatalf("Predict error = %v, want ErrUnpredictable", err)
			}
		})
	}
}
