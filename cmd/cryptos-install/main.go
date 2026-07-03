// Command cryptos-install provisions a bare-metal disk for CryptOS: it
// lays out the GPT (ESP + cryptos-state), formats the ESP, and writes the
// signed UKI to the removable-media fallback path. The cryptos-state
// partition is left unformatted — the node LUKS-formats and TPM-seals it
// on first boot.
//
// Run on the target (or a live USB) as root. THE TARGET DISK IS WIPED.
package main

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
	"flag"
	"fmt"
	"os"

	"github.com/CryptOS-PKI/cryptos/internal/install"
)

func main() {
	var (
		o   install.Options
		yes bool
	)
	flag.StringVar(&o.Disk, "disk", "", "target block device to WIPE (e.g. /dev/nvme0n1)")
	flag.StringVar(&o.UKI, "uki", "", "path to the signed UKI to install")
	flag.StringVar(&o.StateLabel, "state-label", "cryptos-state", "GPT name for the state partition")
	flag.StringVar(&o.ESPLabel, "esp-label", "EFI", "GPT name for the EFI System Partition")
	flag.IntVar(&o.ESPSizeMiB, "esp-size-mib", 512, "EFI System Partition size in MiB")
	flag.BoolVar(&yes, "yes", false, "confirm: the target disk will be ERASED")
	flag.Parse()

	if o.Disk == "" || o.UKI == "" {
		fmt.Fprintln(os.Stderr, "cryptos-install: --disk and --uki are required")
		flag.Usage()
		os.Exit(2)
	}
	if !yes {
		fmt.Fprintf(os.Stderr, "cryptos-install: this ERASES %s. Re-run with --yes to proceed.\n", o.Disk)
		os.Exit(1)
	}

	mnt, err := os.MkdirTemp("", "cryptos-esp-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "cryptos-install:", err)
		os.Exit(1)
	}
	defer func() { _ = os.RemoveAll(mnt) }()

	if err := install.Install(context.Background(), o, install.ExecRunner{}, mnt, install.CopyFile, install.RealDeps()); err != nil {
		fmt.Fprintln(os.Stderr, "cryptos-install:", err)
		os.Exit(1)
	}
	fmt.Printf("cryptos-install: provisioned %s; the node will format + seal %s on first boot\n", o.Disk, o.StateLabel)
}
