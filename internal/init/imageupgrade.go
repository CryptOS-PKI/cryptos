package init

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

// The node side of in-place image upgrades (#208): the grpc.ImageUpgrader a
// running node serves, over internal/imageupgrade and the real ESP.
//
// The state partition is never opened here. That is the whole point of the
// feature: an OS change stops being a re-provision that destroys the CA key.

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	cgrpc "github.com/CryptOS-PKI/cryptos/internal/grpc"
	"github.com/CryptOS-PKI/cryptos/internal/imageupgrade"
	"github.com/CryptOS-PKI/cryptos/internal/reset"
)

// imageActivateRebootDelay lets the ActivateImageResponse flush before the
// connection drops, the same handoff the resetter and the installer use: a
// direct reboot inside the handler races the reply and the caller cannot tell
// success from a dropped connection.
const imageActivateRebootDelay = 2 * time.Second

// espMounter mounts the node's EFI System Partition, runs fn against the mount
// point, and unmounts -- including when fn fails, or the partition stays busy
// and the next upgrade cannot mount it.
//
// readWrite is a parameter rather than always true so reading status cannot
// modify the boot partition of a production CA even by accident.
type espMounter func(readWrite bool, fn func(root string) error) error

// imageUpgradeOptions carries the dependencies for a nodeImageUpgrader.
type imageUpgradeOptions struct {
	// CACN returns this node's current CA common name, echoed by the caller
	// to authorize a reboot. It is called per Activate so a CA certificate
	// installed after boot is honoured. Empty (an unprovisioned node) makes
	// every confirmation fail with reset.ErrNoCAIdentity.
	CACN func() string
	// Mount mounts the ESP for one operation.
	Mount espMounter
	// Reboot restarts the node. It runs only after a confirmed Activate.
	Reboot func()
	// Release is the certificate an incoming image must be signed by, from
	// internal/release. Nil is refused: a build with no release certificate
	// serves no upgrade RPCs at all rather than accepting anything.
	Release *x509.Certificate
	// Running is the SHA-256 (hex) of the image this node booted, captured at
	// startup before anything could stage over it. It is what makes
	// reboot_pending answerable: once an upgrade is staged, the file on the
	// boot path is no longer the file that is running.
	Running string
	// Version is the build version string of the running image, which is what
	// an operator actually recognises.
	Version string
}

// nodeImageUpgrader implements grpc.ImageUpgrader.
type nodeImageUpgrader struct {
	opts imageUpgradeOptions
}

func newImageUpgrader(opts imageUpgradeOptions) (*nodeImageUpgrader, error) {
	if opts.CACN == nil {
		return nil, errors.New("init: image upgrade: a CA CN lookup is required")
	}
	if opts.Mount == nil {
		return nil, errors.New("init: image upgrade: a mounter is required")
	}
	if opts.Reboot == nil {
		return nil, errors.New("init: image upgrade: a reboot function is required")
	}
	if opts.Release == nil {
		return nil, errors.New("init: image upgrade: a release certificate is required")
	}

	return &nodeImageUpgrader{opts: opts}, nil
}

// Stage verifies the image and installs it as the one the firmware will boot,
// retaining the current image. It does not reboot.
func (u *nodeImageUpgrader) Stage(_ context.Context, image, signature []byte) (*cryptosv1.ImageStatus, error) {
	// Verified before the ESP is mounted at all, let alone writable. An image
	// the node cannot attribute never gets near the boot partition of a
	// production CA, and the stager verifies again on its own behalf -- cheap
	// next to the upload, and it keeps that guarantee a property of the stager
	// rather than of this caller remembering to check.
	if err := imageupgrade.Verify(image, signature, u.opts.Release); err != nil {
		return nil, fmt.Errorf("%w: %w", cgrpc.ErrImageNotVerified, err)
	}

	var st imageupgrade.Status
	err := u.opts.Mount(true, func(root string) error {
		stager, newErr := imageupgrade.New(dirFS{root: root}, u.opts.Release)
		if newErr != nil {
			return newErr
		}
		var stageErr error
		st, stageErr = stager.Stage(image, signature)

		return stageErr
	})
	if err != nil {
		return nil, fmt.Errorf("init: stage image: %w", err)
	}

	return u.imageStatus(st), nil
}

// Rollback puts the retained image back on the boot path. It does not reboot.
func (u *nodeImageUpgrader) Rollback(_ context.Context) (*cryptosv1.ImageStatus, error) {
	var st imageupgrade.Status
	err := u.opts.Mount(true, func(root string) error {
		stager, newErr := imageupgrade.New(dirFS{root: root}, u.opts.Release)
		if newErr != nil {
			return newErr
		}
		if rbErr := stager.Rollback(); rbErr != nil {
			return rbErr
		}
		var statusErr error
		st, statusErr = stager.Status()

		return statusErr
	})
	if err != nil {
		if errors.Is(err, imageupgrade.ErrNoPrevious) {
			// Translated to this package's sentinel so the handler can answer
			// FailedPrecondition without importing the implementation.
			return nil, cgrpc.ErrNoPreviousImage
		}

		return nil, fmt.Errorf("init: roll back image: %w", err)
	}

	return u.imageStatus(st), nil
}

// Activate reboots the node so a staged image starts running.
//
// The confirmation is checked with reset.CheckConfirm, as the resetter checks
// its own, against the CA CN looked up now: fail closed on an empty CA CN
// (reset.ErrNoCAIdentity) or an empty or different confirmation
// (reset.ErrConfirmMismatch), with a constant-time compare.
//
// It also refuses when nothing is staged. Rebooting an issuing CA takes every
// dependent system's certificate operations down with it, and doing that to
// boot the same image the node is already running is an outage with nothing to
// show for it -- far more likely a mistake than an intention.
func (u *nodeImageUpgrader) Activate(ctx context.Context, confirmCommonName string) error {
	if err := reset.CheckConfirm(u.opts.CACN(), confirmCommonName); err != nil {
		return err
	}

	st, err := u.Status(ctx)
	if err != nil {
		return err
	}
	if !st.GetRebootPending() {
		return errors.New("init: activate image: no staged image; the node is already running what it would boot")
	}

	u.opts.Reboot()

	return nil
}

// Status reports the images on the ESP and the one running.
func (u *nodeImageUpgrader) Status(_ context.Context) (*cryptosv1.ImageStatus, error) {
	var st imageupgrade.Status
	err := u.opts.Mount(false, func(root string) error {
		stager, newErr := imageupgrade.New(dirFS{root: root}, u.opts.Release)
		if newErr != nil {
			return newErr
		}
		var statusErr error
		st, statusErr = stager.Status()

		return statusErr
	})
	if err != nil {
		return nil, fmt.Errorf("init: read image status: %w", err)
	}

	return u.imageStatus(st), nil
}

func (u *nodeImageUpgrader) imageStatus(st imageupgrade.Status) *cryptosv1.ImageStatus {
	return &cryptosv1.ImageStatus{
		ActiveSha256:   st.ActiveDigest,
		PreviousSha256: st.PreviousDigest,
		RebootPending:  st.ActiveDigest != u.opts.Running,
		RunningSha256:  u.opts.Running,
		RunningVersion: u.opts.Version,
	}
}

// dirFS is imageupgrade.FS over a mounted ESP.
//
// Durability comes from the unmount the mounter performs when the operation
// finishes, which is the real barrier on vfat; the per-file Sync here just
// narrows the window if the node loses power mid-upgrade.
type dirFS struct {
	root string
}

func (d dirFS) path(rel string) string { return filepath.Join(d.root, filepath.FromSlash(rel)) }

func (d dirFS) Exists(rel string) (bool, error) {
	_, err := os.Stat(d.path(rel))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	return true, nil
}

func (d dirFS) ReadFile(rel string) ([]byte, error) { return os.ReadFile(d.path(rel)) }

func (d dirFS) Remove(rel string) error { return os.Remove(d.path(rel)) }

func (d dirFS) Rename(from, to string) error { return os.Rename(d.path(from), d.path(to)) }

func (d dirFS) WriteFile(rel string, data []byte) error {
	full := d.path(rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(full, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()

		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()

		return err
	}

	return f.Close()
}

// digestFile returns the SHA-256 (hex) of rel under a mounted ESP, or an empty
// string when it is not there. It is how a booting node learns which image it
// is running: at startup the file on the boot path is, by definition, the one
// the firmware just booted.
func digestFile(mount espMounter, rel string) (string, error) {
	var out string
	err := mount(false, func(root string) error {
		data, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if errors.Is(readErr, fs.ErrNotExist) {
			return nil
		}
		if readErr != nil {
			return readErr
		}
		sum := sha256.Sum256(data)
		out = hex.EncodeToString(sum[:])

		return nil
	})

	return out, err
}
