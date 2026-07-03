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
	"os"

	"github.com/CryptOS-PKI/cryptos/internal/config"
)

// errEnterMaintenance signals that the persisted config is absent (on an
// already-installed node) or unparseable, so Boot should drop to maintenance
// mode (Talos: no valid config -> maintenance) rather than reboot-loop.
var errEnterMaintenance = errors.New("init: config unavailable — maintenance")

// loadOrSeedConfig returns the node's machine config. It reads the persisted
// config from the state fs; on first boot (freshly formatted, nothing persisted)
// it seeds from the baked file once and persists it. Missing-on-installed or
// unparseable persisted config returns errEnterMaintenance.
func loadOrSeedConfig(store *config.FileStore, bakedPath string, firstBoot bool) (*config.Config, error) {
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
	if !firstBoot {
		return nil, fmt.Errorf("%w: no persisted config on an installed node", errEnterMaintenance)
	}
	// First boot: seed from the baked file (a build artifact; invalid = hard fail).
	baked, err := os.ReadFile(bakedPath)
	if err != nil {
		return nil, fmt.Errorf("init: read baked seed %s: %w", bakedPath, err)
	}
	cfg, err := config.Parse(baked)
	if err != nil {
		return nil, fmt.Errorf("init: baked seed config invalid: %w", err)
	}
	if _, err := store.Write(baked); err != nil {
		return nil, fmt.Errorf("init: persist seed config: %w", err)
	}
	return cfg, nil
}
