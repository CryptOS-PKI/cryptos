// Package netlink configures NICs via raw rtnetlink. Phase 1 brings up
// loopback and a single physical interface with a static IPv4 address
// from machine config; DHCP is Phase 2.
//
// No third-party netlink library is pulled in for Phase 1 — the surface
// we need is small enough that golang.org/x/sys/unix is sufficient.
package netlink

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
