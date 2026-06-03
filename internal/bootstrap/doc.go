// Package bootstrap loads and verifies the pre-stamped bootstrap admin
// certificate from machine config and orchestrates its rotation at the
// end of the first-boot ceremony.
//
// Phase 1 (per locked answer #2): the bootstrap cert is single-use. The
// last step of the first ceremony is the operator enrolling their real
// long-term admin cert via the StartCeremony stream; the bootstrap cert
// is then revoked. PID 1 refuses to bring up the network listener until
// either a bootstrap cert OR a steady-state admin cert is loaded.
package bootstrap

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
