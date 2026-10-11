// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package iec6205621 is the IEC 62056-21 protocol (the local readout of
// meters formerly known as IEC 1107) from the client's side: messages and
// their block check character (clause 6.3), identification and option
// select, modes A to E (6.4), programming mode with the R1 to R6, W1 to
// W5, E2 and B0/B1 commands and partial blocks (6.4.7), the annex C
// formatted codes, the annex B wake-up and fast wake-up of battery
// meters, mode D pushes, and the mode E switch to the binary HDLC phase,
// after which the line is handed to a DLMS/COSEM client
// (Session.BinaryPort with cosem.NewPortClient).
//
// A Line is an optical probe or a serial port (reopened at each rate), or
// a transparent serial-to-IP converter, with the 7E1 parity emulated over
// 8-bit bytes when the converter runs 8N1. OpenSession signs on and reads
// the identification; Session runs the exchanges, repeating on NAK and
// breaking off with B0 after three tries (annex A). OBIS names the
// reduced IDs (obis.go). The simulator is package iec6205621sim.
package iec6205621
