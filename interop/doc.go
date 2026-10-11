// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package interop holds tests only: github.com/cB-Sigma/dlms against
// Gurux's DLMS/COSEM implementations, written independently of ours.
//
//   - Our cosem client reads Gurux.DLMS.Java's server example (logical
//     and short name servers, over the IEC 62056-4-7 wrapper and over
//     HDLC on TCP): every security level the example offers, security
//     suite 1, general-glo ciphering, a dedicated key, ACCESS and short
//     name referencing (interop_test.go, v020_test.go).
//   - Gurux's Python client (gurux-dlms) reads and writes our server
//     package (server_interop_test.go with testdata/gurux_client.py):
//     logical and short names, suites 0 to 2, every ciphering form.
//   - gurux_vectors_test.go checks our ciphering, key wrap and ACCESS
//     encoding against the vectors of Gurux's published unit tests.
//
// The tests start the peers themselves in Docker: a pinned Maven image
// fetches the Gurux.DLMS.Java sources at a pinned commit, builds the
// server example and runs it (testdata/gurux-server.sh says the settings
// changed); a pinned Python image installs a pinned gurux-dlms. Vectors
// are fetched at a pinned commit when the test runs. No Gurux code or data
// is kept in this repository. The tests run only when SIGMA_DLMS_INTEROP=1
// (and docker is on PATH), and need network access:
//
//	cd libs/dlms/interop && SIGMA_DLMS_INTEROP=1 GOWORK=off go test -v -timeout 30m ./...
package interop
