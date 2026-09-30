// Package timesync is the node's client-only SNTPv4 (RFC 4330, and RFC 5905
// section 14): a bounded sync at boot that steps or slews the clock, periodic
// polls after that, and a clock floor the clock is never stepped behind. It
// never serves time.
package timesync

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
