// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package cosem is a DLMS/COSEM client (logical name referencing): the
// application association (AARQ, AARE, RLRQ, RLRE) with low-level and
// high-level security authentication (mechanisms 1 to 7), the security
// suites 0 to 2 with service-specific, general-glo, general-ded and general
// ciphering, general signing, third-party protection and V.44 compression
// (IEC 62056-5-3:2023, the DLMS UA Green Book), get, set and action with
// block transfer, the security setup object (class 64: key transfer and
// agreement, certificates), push reception (data-notification, general
// block transfer, HDLC pushes), the gateway protocol of IEC 62056-5-3
// annex C for meters behind a data concentrator, profile reading by range,
// meter-initiated connections, local serial lines with the IEC 62056-21
// mode E opening, and invocation counters kept across restarts.
//
// The xDLMS services are those of gosem
// (gitlab.com/circutor-library/gosem, MIT), configured without
// ciphering: SecureTransport sits between gosem and the supporting layers
// (packages wrapper, hdlc, phy and gateway of this module) and applies
// the protection itself, so every combination of suite, policy, key and
// ciphering form works.
//
// The main entry points:
//
//   - SecurityConfig turns text settings into the HLS value an
//     association uses; Associate opens one association over a transport
//     the caller opened; Client keeps one meter's associations, its
//     invocation counter and the system title it named.
//   - ICReservation, Counter and PushCounter keep invocation counters
//     through an iotsec.Store, so a restart never repeats one.
//   - OpenProtectedPush, DecodeDataNotification, PushSetupOf and MapPush
//     open and map pushes; ServeHDLCPushes reads pushes in HDLC frames;
//     InboundConn carries a meter-initiated connection.
//   - Gateway is the shared connection to a DCU (gateway or
//     logical-device mode).
//   - ReadCaptureObjects, ReadProfileRange and ProfileRow read profiles.
//   - SecuritySetup runs the methods of the security setup object.
//   - NewPortClient runs a client over a port another protocol opened (an
//     optical head after an IEC 62056-21 mode E switch).
//   - Seal, Open, Request and Exchange carry DLMS APDUs inside another
//     protocol (wireless and wired M-Bus).
//
// A crypto policy (iotsec.CryptoPolicy) may veto an authentication
// mechanism at association time (AssociationConfig.Policy,
// MechanismAlgorithm). Refusals of pushes for their protection are
// *PushSecurityError with a stable event name for a security log
// (iotsec.SecurityEvent).
//
// Comments cite the clauses they implement; "F-nnnn" names a finding in
// SigmaM2M's register of specification defects (see PROVENANCE.md).
package cosem
