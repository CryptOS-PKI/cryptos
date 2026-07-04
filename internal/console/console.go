package console

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
