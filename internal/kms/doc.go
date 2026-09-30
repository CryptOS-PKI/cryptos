// Package kms seals and unseals the state-partition key with an external KMS
// (envelope encryption). It exposes a Provider interface and a generic HTTP
// seal/unseal adapter (the Talos KMS model); the node holds only the sealed
// blob and asks the KMS to reverse the operation at boot.
package kms

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
