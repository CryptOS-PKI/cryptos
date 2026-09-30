package audit

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
	"strings"

	cryptosv1 "github.com/CryptOS-PKI/api/go/cryptos/v1"
)

// DetailSerial is the details key under which an entry records the hex serial
// of the certificate a call acted on.
const DetailSerial = "serial_hex"

// targetDetails are the details keys that name what a call acted on, in the
// order Describe prefers them.
var targetDetails = []string{DetailSerial, "request_dns_names"}

// actions describes the calls an operator looks for in the log. Any other
// call is described by its method name.
var actions = map[string]string{
	"StartCeremony":                "ran the first-boot ceremony",
	"ApplyConfig":                  "applied a machine config",
	"SetManagement":                "changed the Fleet Manager link",
	"IssueLeaf":                    "issued a leaf certificate",
	"SignSubordinateCSR":           "signed a subordinate CA certificate",
	"SubmitSubordinateCertificate": "installed this node's signed CA certificate",
	"RevokeCertificate":            "revoked a certificate",
	"BeginKeyRotation":             "began a CA key rotation",
	"CompleteKeyRotation":          "completed a CA key rotation",
	"SubmitRenewedCertificate":     "installed a renewed CA certificate",
	"ExportCAKey":                  "exported an encrypted CA key backup",
	"ImportCAKey":                  "restored the CA key from a backup",
	"Reboot":                       "rebooted or powered off the node",
	"RemoteReset":                  "reset the node",
	"Reset":                        "reset the node",
	"StageImage":                   "staged an OS image",
	"ActivateImage":                "activated a staged OS image",
	"RollbackImage":                "rolled back to the previous OS image",
}

// MethodName returns the method name alone from a full gRPC method name.
func MethodName(fullMethod string) string {
	return fullMethod[strings.LastIndexByte(fullMethod, '/')+1:]
}

// Describe derives, for display, what an entry's call acted on (empty when the
// entry doesn't record it) and a one-line summary of the entry. Neither is
// part of the chain.
func Describe(ev *cryptosv1.AuditEvent) (target, summary string) {
	for _, key := range targetDetails {
		if v := ev.GetDetails()[key]; v != "" {
			target = v
			break
		}
	}
	method := MethodName(ev.GetRpcMethod())
	summary = actions[method]
	if summary == "" {
		summary = "called " + method
	}
	if target != "" {
		summary += ": " + target
	}
	switch ev.GetOutcome() {
	case cryptosv1.Outcome_OUTCOME_DENIED:
		summary += " (denied)"
	case cryptosv1.Outcome_OUTCOME_ERROR:
		summary += " (failed)"
	}
	return target, summary
}
