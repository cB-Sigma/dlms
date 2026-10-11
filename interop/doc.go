// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package interop holds tests only: the cosem client of
// github.com/cB-Sigma/dlms reads a meter served by Gurux's DLMS/COSEM
// server example for Java, an implementation written independently of
// ours, over the IEC 62056-4-7 wrapper and over HDLC on TCP.
//
// The tests start the peer themselves in Docker: a pinned Maven image
// fetches the Gurux.DLMS.Java sources at a pinned commit, builds the
// server example and runs it (testdata/gurux-server.sh says the one
// setting changed). gurux_vectors_test.go checks our ciphering and key
// wrap against the hexadecimal vectors of Gurux's published unit tests,
// fetched at a pinned commit when the test runs. No Gurux code or data is
// kept in this repository. The tests run only when SIGMA_DLMS_INTEROP=1
// (and, for the server, docker is on PATH), and need network access:
//
//	cd libs/dlms/interop && SIGMA_DLMS_INTEROP=1 GOWORK=off go test -v -timeout 20m ./...
package interop
