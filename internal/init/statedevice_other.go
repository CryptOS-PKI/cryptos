//go:build !linux

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

import "fmt"

// resolveStateDevice is Linux-only; init runs only on the CryptOS image. This
// stub keeps the package buildable on the dev host.
func resolveStateDevice(label string) (string, error) {
	return "", fmt.Errorf("init: resolveStateDevice(%q): state-device resolution is linux-only", label)
}
