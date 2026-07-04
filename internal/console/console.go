package console

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
	"fmt"
	"io"
)

// shield is the classic ASCII shield + wordmark shown once at boot.
const shield = `      .-----------------.
     |                 |
     |     CryptOS     |
     |       PKI       |
      '.               .'
        '.           .'
          '.       .'
            '.   .'
              '-'
`

// Banner returns the branded boot banner (shield + wordmark).
func Banner() string { return shield }

// StepState is a bring-up step's outcome marker.
type StepState int

const (
	StepRunning StepState = iota // ".."
	StepOK                       // "ok"
	StepFail                     // "!!"
)

func (s StepState) marker() string {
	switch s {
	case StepOK:
		return "ok"
	case StepFail:
		return "!!"
	default:
		return ".."
	}
}

// Renderer writes the branded boot sequence to the node console.
type Renderer struct{ w io.Writer }

// NewRenderer returns a Renderer writing to w.
func NewRenderer(w io.Writer) *Renderer { return &Renderer{w: w} }

// Banner writes the shield banner once, at the start of boot.
func (r *Renderer) Banner() error {
	_, err := io.WriteString(r.w, shield)
	return err
}

// Step writes one bring-up status line, e.g. "   [ok]  state volume".
func (r *Renderer) Step(name string, state StepState) error {
	_, err := fmt.Fprintf(r.w, "   [%s]  %s\n", state.marker(), name)
	return err
}
