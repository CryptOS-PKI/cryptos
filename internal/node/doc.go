// Package node is the typed state layer between the embedded etcd
// datastore (internal/storage/etcd) and the gRPC handlers
// (internal/grpc). Store is the only accessor outside the storage layer
// that reads or writes CryptOS state keys, so etcd paths stay centralized
// in one schema.
//
// The package also provides the concrete IdentityProvider, StatusProvider,
// and ConfigStore that satisfy the dependency interfaces internal/grpc
// requires, and CommitFirstCeremony — the atomic, identity-guarded
// transaction the first-boot ceremony uses to persist the Root identity.
package node

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
