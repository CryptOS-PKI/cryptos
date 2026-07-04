// Package console renders the branded boot sequence to the node console: a
// classic ASCII shield + wordmark banner shown once, and one clean per-step
// status line ("   [ok]  <name>") for each bring-up stage. It writes to any
// io.Writer and depends only on the standard library, so it is shared by PID 1
// (M1, which points it at /dev/console) and the cryptos-console dashboard (M2).
package console

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
