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
	"context"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
)

// maintenanceStatus is the StatusProvider used in maintenance mode: it reports a
// fixed, store-free status (no etcd exists yet). It signals a node that has
// booted but has no established identity and no persisted state.
type maintenanceStatus struct{ version string }

func newMaintenanceStatus(version string) *maintenanceStatus {
	return &maintenanceStatus{version: version}
}

// Status implements internal/grpc.StatusProvider.
func (m *maintenanceStatus) Status(context.Context) (*cryptosv1.NodeStatus, error) {
	return &cryptosv1.NodeStatus{
		SoftwareVersion: m.version,
		BootCount:       0,
		FleetManager:    cryptosv1.FleetManagerState_FLEET_MANAGER_STATE_NOT_ENROLLED,
	}, nil
}
