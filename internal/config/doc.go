// Package config parses and validates the YAML machine configuration
// (apiVersion: cryptos.dev/v1alpha1) and persists the applied generation
// to etcd. Phase 1 supports the subset documented in
// plan/specs/phase-1-core.md §7 — role=root only, with a fixed schema.
//
// Validator rejects unknown apiVersion values with INVALID_ARGUMENT.
// Schema additions are additive across phases; breaking changes ship as
// a new apiVersion with an explicit migration path.
package config

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
