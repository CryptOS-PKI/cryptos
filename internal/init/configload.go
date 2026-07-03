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

import (
	"errors"
	"fmt"

	"github.com/CryptOS-PKI/cryptos/internal/config"
)

// errEnterMaintenance signals that the persisted config is absent (on an
// already-installed node) or unparseable, so Boot should drop to maintenance
// mode (Talos: no valid config -> maintenance) rather than reboot-loop.
var errEnterMaintenance = errors.New("init: config unavailable — maintenance")

// espStageAccessors groups the injectable seams for reading and deleting the
// operator config staged on the installed disk's ESP at EFI/cryptos/machine.yaml.
// Both fields may be nil; a nil stageReader is treated as "no stage present".
type espStageAccessors struct {
	// stageReader returns the raw YAML bytes from the ESP stage file, whether
	// the file was present, and any I/O error. A nil stageReader is equivalent
	// to func() (nil, false, nil): no stage present.
	stageReader func() (raw []byte, present bool, err error)
	// stageDeleter removes the stage file from the ESP. Called only after a
	// successful store.Write; a non-nil error is logged but does not abort the
	// boot (the crash-safe design retries on next boot when the stage is still
	// present and no persisted config exists).
	stageDeleter func() error
}

// loadOrSeedConfig returns the node's machine config. Precedence:
//
//  1. Persisted config present in store → use it.
//  2. ESP stage present (stage.stageReader) → parse, persist, delete stage, use it.
//     This path is NOT gated on firstBoot: a crash after format-but-before-persist
//     will leave the state partition empty; re-seeding from the stage on the next
//     boot is correct even though firstBoot is false at that point.
//  3. Otherwise → errEnterMaintenance.
func loadOrSeedConfig(store *config.FileStore, stage espStageAccessors) (*config.Config, error) {
	// 1. Persisted config.
	raw, _, ok, err := store.Read()
	if err != nil {
		return nil, err // state fs I/O error: fail-closed
	}
	if ok {
		cfg, perr := config.Parse(raw)
		if perr != nil {
			return nil, fmt.Errorf("%w: persisted config: %v", errEnterMaintenance, perr)
		}
		return cfg, nil
	}

	// 2. ESP stage (crash-safe; not gated on firstBoot).
	if stage.stageReader != nil {
		stageRaw, present, rerr := stage.stageReader()
		if rerr != nil {
			return nil, fmt.Errorf("init: read ESP stage: %w", rerr)
		}
		if present {
			cfg, perr := config.Parse(stageRaw)
			if perr != nil {
				return nil, fmt.Errorf("init: ESP stage config invalid: %w", perr)
			}
			if _, werr := store.Write(stageRaw); werr != nil {
				return nil, fmt.Errorf("init: persist ESP stage config: %w", werr)
			}
			// Delete the stage only after a successful persist. A failure here is
			// not fatal: the next boot will find no persisted config + stage present
			// and re-seed idempotently.
			if stage.stageDeleter != nil {
				if derr := stage.stageDeleter(); derr != nil {
					// Non-fatal: log via the caller; do not return an error.
					_ = derr
				}
			}
			return cfg, nil
		}
	}

	// 3. Maintenance.
	return nil, fmt.Errorf("%w: no persisted config on an installed node", errEnterMaintenance)
}
