package init

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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	nodev1 "github.com/CryptOS-PKI/cryptos-node/gen/go/cryptos/node/v1"
	"github.com/CryptOS-PKI/cryptos-node/internal/buildinfo"
	"github.com/CryptOS-PKI/cryptos-node/internal/config"
	"github.com/CryptOS-PKI/cryptos-node/internal/node"
	"github.com/CryptOS-PKI/cryptos-node/internal/timesync"
)

const (
	// ipconfigNTPPath is where the kernel's ip= autoconfiguration reports the
	// NTP servers (DHCP option 42) from its lease: one IPv4 address per line,
	// at most three. They are not in /proc/net/pnp.
	ipconfigNTPPath = "/proc/net/ipconfig/ntp_servers"
	// clockFloorFile holds the clock floor on the state volume.
	clockFloorFile = "clock-floor"
	// timeSyncLogLevel is the node's level for time-sync logs. The node has
	// no level knob; debug keeps each poll (a few lines a minute at most)
	// in the kernel log, where a clock problem is diagnosed.
	timeSyncLogLevel = slog.LevelDebug
)

// startTimeSync picks the time source, runs the bounded boot sync and returns
// the engine. The periodic loop is started by the caller. It never fails the
// boot: a node that cannot reach time runs on its hardware clock, with signing
// gated until a later poll succeeds.
func startTimeSync(ctx context.Context, n config.Network, stateMount string) *timesync.Engine {
	logger := slog.New(slog.NewTextHandler(log.Writer(), &slog.HandlerOptions{Level: timeSyncLogLevel}))
	lease, err := readLease(ipconfigNTPPath)
	if err != nil {
		logger.Warn("time sync: could not read the DHCP NTP servers; ignoring the lease", "path", ipconfigNTPPath, "err", err)
	}
	servers, source := timeSourceFor(n, lease)
	logger.Info("time sync source chosen", "source", source.String(), "servers", strings.Join(servers, ","))

	build := parseBuildTime(buildinfo.Get().BuildDate)
	floorPath := filepath.Join(stateMount, clockFloorFile)
	floor, err := timesync.OpenFloor(floorPath, build)
	if err != nil {
		logger.Error("time sync: clock floor unreadable; holding the floor at the image build time", "path", floorPath, "err", err)
	}
	logger.Debug("clock floor loaded", "floor", floor.Get(), "build_time", build)

	e, err := timesync.New(timesync.Config{
		Servers: servers,
		Source:  source,
		Clock:   timesync.SystemClock(),
		Floor:   floor,
		Logger:  logger,
	})
	if err != nil {
		// Only a list longer than MaxServers fails New, and both sources are
		// capped before this point.
		logger.Error("time sync disabled", "err", err)
		e, _ = timesync.New(timesync.Config{Clock: timesync.SystemClock(), Floor: floor, Logger: logger})
		return e
	}
	e.BootSync(ctx)
	return e
}

// wireClockGate connects the signer to the time-sync engine: signing waits for
// the first good sync, and every issued notBefore raises the clock floor.
func wireClockGate(s *node.CASigner, e *timesync.Engine) *node.CASigner {
	return s.WithClockGate(e.SignAllowed).WithIssuedHook(e.NoteIssued)
}

// timeSourceFor picks the node's time servers. network.ntp_servers wins when
// set. Otherwise the servers from the kernel DHCP lease are used. With
// neither, the source is TIME_SOURCE_NONE.
func timeSourceFor(n config.Network, lease []byte) ([]string, nodev1.TimeSource) {
	if len(n.NTPServers) > 0 {
		return n.NTPServers, nodev1.TimeSource_TIME_SOURCE_MACHINE_CONFIG
	}
	if servers := parseIPConfigNTP(lease); len(servers) > 0 {
		return servers, nodev1.TimeSource_TIME_SOURCE_DHCP_LEASE
	}
	return nil, nodev1.TimeSource_TIME_SOURCE_NONE
}

// parseIPConfigNTP extracts the NTP servers from the kernel's option 42 file.
// The lease is input from the network, so each value is validated like a
// configured literal and anything else is dropped.
func parseIPConfigNTP(b []byte) []string {
	var servers []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		a, err := config.ParseNameserver(strings.TrimSpace(sc.Text()))
		if err != nil || seen[a.String()] || len(servers) == config.MaxNTPServers {
			continue
		}
		seen[a.String()] = true
		servers = append(servers, a.String())
	}
	return servers
}

// readLease reads the option 42 file; a missing file is no lease.
func readLease(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("init: read %s: %w", path, err)
	}
	return b, nil
}

// parseBuildTime parses the stamped build date, or returns the zero time for
// a development build with none, which leaves the floor to the state volume.
func parseBuildTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}
