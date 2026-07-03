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
	"fmt"
	"log"
	"net"
	"os/signal"
	"strconv"
	"syscall"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
	cgrpc "github.com/CryptOS-PKI/cryptos/internal/grpc"
	"github.com/CryptOS-PKI/cryptos/internal/init/netlink"
)

// nopAuditor drops audit events. Maintenance mode has no durable state store to
// persist an audit chain to, and it serves only the unauthenticated GetStatus,
// so there is nothing meaningful to record. The grpc audit interceptors require
// a non-nil Auditor, so maintenance supplies this no-op.
type nopAuditor struct{}

func (nopAuditor) Append(*cryptosv1.AuditEvent) error { return nil }

// runMaintenance brings up the limited maintenance service. Loopback is up and
// the kernel has configured the primary interface via ip=dhcp, so we only serve
// the management API with a self-signed maintenance cert and NO client
// verification (Talos --insecure). No TPM, LUKS, etcd, or ceremony. Parks until
// a shutdown signal, then returns so PID 1 reboots.
func runMaintenance(ctx context.Context) error {
	if err := netlink.BringUpLoopback(); err != nil {
		return err
	}
	serverCert, err := GenerateServerCert([]string{"localhost"})
	if err != nil {
		return err
	}
	srv, err := cgrpc.NewMaintenance(cgrpc.ServerConfig{
		TLSConfig: MaintenanceServerTLSConfig(serverCert),
		Auditor:   nopAuditor{},
		Status:    newMaintenanceStatus(Version),
	})
	if err != nil {
		return err
	}
	addr := net.JoinHostPort("0.0.0.0", strconv.Itoa(ManagementPort))
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("init: maintenance listen %s: %w", addr, err)
	}
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()
	log.Printf("MAINTENANCE mode: management API on %s (client auth OFF); no state disk present", addr)

	sigCtx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	<-sigCtx.Done()
	log.Printf("shutdown signal received")
	return nil
}
