// Package ukipcr predicts the PCR 11 value a Unified Kernel Image will leave
// behind when systemd-stub boots it.
//
// A node whose state key is sealed to PCR 11 can only take a new image if the
// key is sealed again, before the reboot, to the value the new image will
// measure. The stub's measurement is deterministic and depends only on the
// image bytes: for each UKI payload section present, in the stub's fixed
// order rather than the order of the PE section table, it extends PCR 11 with
// the SHA-256 of the section name including its NUL terminator, then with the
// SHA-256 of the section contents as loaded in memory (VirtualSize bytes,
// zero-filled past the raw data). .pcrsig is skipped because it signs the
// result of the measurement. Nothing else in a CryptOS boot extends PCR 11:
// there is no systemd userspace to add phase measurements, and init never
// touches it.
//
// Prediction refuses any image it cannot be sure about instead of guessing:
// unknown sections, a section whose name only prefix-matches a payload name
// (the stub matches by prefix, so ".dtbauto" would count as ".dtb"), repeated
// payload sections, and multi-profile images. A wrong prediction here is a
// node that cannot unseal its state on the next boot, so a refusal is always
// the cheaper failure.
package ukipcr

/*
Apache License 2.0

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
	"debug/pe"
	"errors"
	"fmt"
	"strings"
)

// PCR is the PCR systemd-stub measures the UKI payload into.
const PCR = 11

// measuredSections is systemd-stub's payload section order (its
// unified_sections table, v255 through v257, minus the entries this package
// refuses). The order is the stub's, never the file's.
var measuredSections = []string{
	".linux", ".osrel", ".cmdline", ".initrd", ".ucode", ".splash",
	".dtb", ".uname", ".sbat", ".pcrpkey",
}

// ignoredSections are sections the stub does not measure: its own code and
// data, and .pcrsig, which signs the measurement and so cannot be part of it.
var ignoredSections = map[string]bool{
	".text": true, ".rodata": true, ".rdata": true, ".data": true, ".bss": true,
	".reloc": true, ".sdmagic": true, ".pdata": true, ".xdata": true,
	".pcrsig": true,
}

// ErrUnpredictable is wrapped by every refusal to predict, so a caller can
// tell "this image cannot be predicted" from an I/O failure.
var ErrUnpredictable = errors.New("ukipcr: PCR 11 cannot be predicted for this image")

// Prediction is the PCR 11 value an image leaves after the stub has run,
// starting from the reset value (all zeros).
type Prediction struct {
	// Value is the SHA-256 bank value of PCR 11.
	Value []byte
	// Sections lists the sections measured, in measurement order, for logs.
	Sections []string
}

// Predict returns the PCR 11 value systemd-stub will measure for image.
func Predict(image []byte) (Prediction, error) {
	f, err := pe.NewFile(bytes.NewReader(image))
	if err != nil {
		return Prediction{}, fmt.Errorf("%w: not a PE image: %w", ErrUnpredictable, err)
	}
	defer func() { _ = f.Close() }()

	found := make(map[string]*pe.Section, len(measuredSections))
	for _, s := range f.Sections {
		name := s.Name
		if ignoredSections[name] {
			continue
		}
		if name == ".profile" {
			return Prediction{}, fmt.Errorf("%w: multi-profile images are not supported", ErrUnpredictable)
		}
		known := ""
		for _, m := range measuredSections {
			if strings.HasPrefix(name, m) {
				known = m
				break
			}
		}
		switch {
		case known == "":
			return Prediction{}, fmt.Errorf("%w: unknown section %q", ErrUnpredictable, name)
		case known != name:
			return Prediction{}, fmt.Errorf("%w: section %q would be measured as %q", ErrUnpredictable, name, known)
		case found[name] != nil:
			return Prediction{}, fmt.Errorf("%w: section %q appears twice", ErrUnpredictable, name)
		}
		found[name] = s
	}
	if found[".linux"] == nil {
		return Prediction{}, fmt.Errorf("%w: no .linux section, so this is not a UKI", ErrUnpredictable)
	}

	pcr := make([]byte, sha256.Size)
	var measured []string
	for _, name := range measuredSections {
		s := found[name]
		if s == nil || s.VirtualSize == 0 {
			// The stub treats a zero-sized section as absent.
			continue
		}
		data, err := loaded(s, len(image))
		if err != nil {
			return Prediction{}, err
		}
		pcr = extend(pcr, append([]byte(name), 0))
		pcr = extend(pcr, data)
		measured = append(measured, name)
	}

	return Prediction{Value: pcr, Sections: measured}, nil
}

// loaded returns a section's contents as the firmware maps them: VirtualSize
// bytes, the raw data truncated or zero-filled to fit.
//
// A section is never larger in memory than the whole image: payload sections
// are file-backed, and the bound keeps a malformed header from asking for
// gigabytes.
func loaded(s *pe.Section, limit int) ([]byte, error) {
	if int(s.VirtualSize) > limit {
		return nil, fmt.Errorf("%w: section %s claims %d bytes in memory", ErrUnpredictable, s.Name, s.VirtualSize)
	}
	raw, err := s.Data()
	if err != nil {
		return nil, fmt.Errorf("ukipcr: read section %s: %w", s.Name, err)
	}
	out := make([]byte, s.VirtualSize)
	copy(out, raw)

	return out, nil
}

// extend is TPM2_PCR_Extend on the SHA-256 bank for an event over data.
func extend(pcr, data []byte) []byte {
	d := sha256.Sum256(data)
	h := sha256.New()
	h.Write(pcr)
	h.Write(d[:])

	return h.Sum(nil)
}
