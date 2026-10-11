# dlms

A DLMS/COSEM client and server for smart meters in pure Go, with the COSEM interface classes, HDLC, the wrapper, IEC 62056-21, DLMS over NB-IoT and LoRaWAN, OBIS and India's IS 15959 catalogue.

[![Go Reference](https://pkg.go.dev/badge/github.com/cB-Sigma/dlms.svg)](https://pkg.go.dev/github.com/cB-Sigma/dlms) [![test](https://github.com/cB-Sigma/dlms/actions/workflows/test.yml/badge.svg)](https://github.com/cB-Sigma/dlms/actions/workflows/test.yml) [![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/go-1.25-00ADD8.svg)](go.mod)

The client associates with no, low or high-level security (mechanisms 2
to 7, security suites 0 to 2, every ciphering form, general signing,
third-party protection, V.44 compression), reads, writes and acts with
block transfer, reads profiles by range, opens pushes, reaches meters
behind data concentrators, and keeps invocation counters across
restarts, with logical or short name referencing and the ACCESS service.
The server package is the meter side: associations with the same
mechanisms and suites, GET, SET, ACTION, ACCESS and the short name
services with block transfer and general block transfer, and pushes,
serving the typed COSEM objects of package classes (40 interface
classes). Below them are the IEC 62056-46 HDLC data link, the IEC 62056-42
physical layer with Hayes modems, the IEC 62056-4-7 wrapper over TCP and
UDP, the gateway prefix, and a LoRaWAN bridge with SCHC. The A-XDR and
xDLMS APDU encodings come from
[gosem](https://gitlab.com/circutor-library/gosem) (MIT); security,
transports and everything above are this module's. No cgo. It was written
for SigmaM2M, a oneM2M platform, where it serves its DLMS/COSEM, IEC
62056-21 and M-Bus integrations, and has no dependency on it.

## Features

| Area | Implemented | Not implemented |
|---|---|---|
| Client (IEC 62056-5-3:2023, Green Book) | Logical name referencing, with or without the ciphering application context (`applicationContext`: automatic, `ln`, `ln-ciphering`, `sn` or `sn-ciphering`); short name referencing (`referencing: sn`: read, write, parameterized access, data blocks, methods, base names from the association SN object list, HLS through the association SN object); the ACCESS service (`Client.Access`, in general-glo or general-ded ciphering when protected); raw exchanges on an association (`Association.Exchange`); image transfer as a state machine (`Client.TransferImage`: resume, resend of missing blocks, verify, activate, status polling); mechanisms 0 to 7; suites 0, 1 and 2; authentication, encryption or both; global and dedicated keys; service-specific, general-glo, general-ded and general ciphering (identified, wrapped, one-pass and static agreed keys); general signing; the broadcast key and unconfirmed broadcast associations; third-party protection; V.44 compression; ciphered release; replay checks; key transfer and agreement, key pairs and certificates of class 64; pushes (data-notification, general-glo, general block transfer, HDLC; encryption-only pushes only on opt-in); data concentrators in gateway and logical-device mode; profile reading by range; identity check; a crypto policy hook at association time | Mechanism 2 is the common AES-ECB reading and is manufacturer specific (confirm per make); key rotation as a client state machine (only its protocol steps are here); short name writes in data blocks |
| Server (IEC 62056-5-3:2023, package `server`) | Associations per client address: no security, low-level, HLS mechanisms 2 to 7; suites 0, 1 and 2; authenticated, encrypted or both; global and dedicated keys; service-specific, general-glo and general-ded ciphering; the broadcast key; invocation counter checks and a counter object; ciphered release; unconfirmed associations. GET, SET and ACTION normal, with list and in data blocks both ways; ACCESS; short name read, write and unconfirmed write with parameterized access and data blocks; general block transfer; access rights per association; the current association LN or SN object with its object list; data-notification pushes (plain or general-glo) to TCP, UDP or HDLC links and from a push setup object; the wrapper over TCP and UDP and HDLC | General ciphering with key agreement and general signing on the server side (the client has them; dlms-sim's meter answers them); third-party protection and compression on the server side |
| COSEM objects (IEC 62056-6-2:2023, package `classes`) | 40 interface classes as data (attributes, methods, short name offsets); typed Go objects for data, registers (3, 4, 5), register activation, profile generic (capture, by range, by entry, FIFO), clock, script table, schedule, special days, associations LN and SN (object lists encoded and parsed), SAP assignment, image transfer (initiate, blocks, verify, activate), IEC local port, activity calendar, register monitor, single action schedule, IEC HDLC setup, push setup, TCP-UDP and IPv4 setup, security setup, disconnect control, limiter; `Generic` for the others | Account (111), charge (113), M-Bus slave port setup (25); push setup versions above 0; profile sort methods other than FIFO |
| HDLC (IEC 62056-46, ISO/IEC 13239) | Frame format type 3; 1-, 2- and 4-octet addresses; SNRM/UA negotiation (information fields up to 2030, windows up to 7); segmentation both ways; RR polling; RNR; FRMR; DM; UI frames; the inactivity time-out; multi-drop lines on one connection | Modulo 128 numbering; sending segmented UI frames (they are accepted) |
| Physical layer (IEC 62056-42) | PH services over a TCP connection to a converter; Hayes dialling, answering, escape and hang-up; the identification service | Collisions of several meters calling at once |
| Wrapper (IEC 62056-4-7, 62056-9-7) | Header checks; whole WPDUs from TCP however they are split; one WPDU per UDP datagram; reserved wPorts | |
| Gateway (IEC 62056-5-3 annex C) | E6/E7 prefix with network ID and physical address | Vendor concentrator variants; the IEC 62056-8-20 mesh |
| NB-IoT and LoRaWAN | UDP from behind carrier NAT with reply windows, sleeping meters, a command queue; SCHC over LoRaWAN (RFC 8724, RFC 9011) with settable FPorts, rules and header; regional limits | The DLMS UA LoRaWAN profile is not public: its choices are settings; network servers are the application's (`NetworkServer`) |
| IEC 62056-21 | Modes A to E, programming mode, annex C formatted codes, annex B wake-ups, mode D, the mode E hand-over to HDLC; 7E1 emulated through converters | Baud rates above 19200 |
| OBIS (IEC 62056-6-1:2023, EN 13757-1:2021) | Value groups A to F with every range, abstract, electricity and media 4 to 9 codes, the COSEM objects of 62056-6-2 with their classes, reduced ID codes, point names that never collide | Names for manufacturer, utility and country specific codes (they keep their code) |
| IS 15959 (India) | Parts 1 (categories A, B, C), 2 (single- and three-phase, with Amendments 1 and 2) and 3 (CT and CT/PT): objects, rights per association, profiles, events, ESW bits, push setups, associations, commands; an IS 16444 event classification | The special days table |

## Choosing a DLMS/COSEM library

Compared from each project's source at the versions named, in October
2026; "tested" means our interop tests ran it (see below). Cells marked
"not checked" were not verified in the source. Check the projects
themselves before relying on a row.

| | this module | gosem v1.3.5 (Go) | Gurux.DLMS.Java (gurux.dlms 4.0.95) | Gurux.DLMS.Python (gurux-dlms 1.0.203) |
|---|---|---|---|---|
| Licence | Apache-2.0 | MIT | GPL-2.0 or a commercial licence | GPL-2.0 or a commercial licence |
| Client / server | both (client tested against Gurux's server, server against Gurux's client) | client | both (tested as a server) | both (tested as a client) |
| Referencing | logical and short name (both tested against Gurux) | logical name | logical and short name (tested) | logical and short name (tested) |
| ACCESS service | yes, client and server (client tested against Gurux's server and vectors) | no | yes (tested as a server; its server answers gets only, acknowledging sets and actions without doing them) | not checked |
| General block transfer | server; client for pushes | no | not checked | fails in its own code when receiving (tested) |
| Typed object model | 40 classes as data, 25 as Go types | no | yes, all classes | yes, all classes |
| Transports | HDLC (with modems and multi-drop), wrapper over TCP and UDP, serial ports, IEC 62056-21 mode E, the gateway prefix, NB-IoT and LoRaWAN with SCHC | HDLC, wrapper, TCP, serial port | HDLC and wrapper (tested); others not checked | HDLC and wrapper (tested); others not checked |
| Low-level security, HLS mechanism 2 | yes (tested both ways) | low-level only: no HLS passes 3 and 4 in its client | yes (tested) | yes (tested) |
| HLS-GMAC (mechanism 5), suite 0 ciphering | yes (tested both ways) | ciphering of suite 0 APDUs; no GMAC pass 3 and 4 | yes (tested) | yes (tested) |
| Mechanisms 3, 4, 6, 7; suites 1 and 2; general ciphering and signing; third party; compression | yes (suite 1 with mechanism 6, general-glo and dedicated keys tested against Gurux's server; suites 0 to 2 in general-glo, general-ded and service-specific ciphering tested against Gurux's client) | no | suite 1, general-glo (tested) | suites 0 to 2, general-glo and general-ded (tested) |
| Block transfer, profile by range | yes (tested both ways) | yes | yes (tested) | yes (tested) |
| Pushes, data concentrators, invocation counters kept across restarts | yes (pushes sent and received) | data notifications received | not checked | not checked |
| OBIS model and IS 15959 catalogue | yes | no | no IS 15959 catalogue | no IS 15959 catalogue |
| cgo / runtime | none, pure Go | none, pure Go | JVM | Python |

This module builds on gosem for the A-XDR and xDLMS APDU encodings and
adds everything above them. Pick it for a Go head end that must talk to
Indian (IS 15959) or other secured meters over HDLC, TCP, UDP, NB-IoT or
LoRaWAN, or for a Go meter, gateway or test bench that must answer as a
meter, without a JVM or a GPL dependency. Pick Gurux when you need every
interface class modelled, server-side general ciphering with key
agreement or signing, or the most widely deployed implementation with
commercial support; pick gosem alone for unsecured or
low-level-security reads where a small dependency matters most.

## Install

```
go get github.com/cB-Sigma/dlms@latest
```

Requires Go 1.25 or later.

## Quick start

```go
import (
	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"

	"github.com/cB-Sigma/dlms/cosem"
	"github.com/cB-Sigma/dlms/wrapper"
)

sec := cosem.SecurityConfig{Name: "M1", Authentication: "hls-gmac", Security: "authenticated-encrypted",
	BlockCipherKey: "...", AuthenticationKey: "...", DedicatedKey: true}
hls, _, err := sec.Build()
r := &cosem.ICReservation{Store: myStore, Name: "M1"} // an iotsec.Store: counters survive a restart
c := cosem.NewClient(cosem.ClientConfig{
	Transport: func(client int) (gdlms.Transport, error) {
		return wrapper.New("tcp", "192.0.2.10:4059", client, 1, 10*time.Second)
	},
	ClientAddress:     48,
	HLS:               hls,
	InvocationCounter: &cosem.FrameCounterObject{OBIS: "0.0.43.1.3.255"},
	Reserve: func(ic uint32, first bool) (uint32, error) { return r.Reserve(ctx, ic, first) },
})
err = c.Connect()
v, err := c.Get(3, "1.0.32.7.0.255", 2) // voltage L1
```

The examples in the documentation that run and check their output are
`cosem.ExampleProtect` (the Green Book's suite 0 example),
`cosem.ExampleICReservation`, `obis.ExampleDescribe`,
`is15959.ExampleGet`, `hdlc.ExampleFrame`, `wrapper.ExampleEncode`,
`gateway.ExampleEncode`, `phy.ExampleIdentifyRequest`,
`iec6205621.ExamplePointName` and `lpwan.ExampleLookupRegion`.
`cosem.ExampleClient` and `iec6205621.ExampleOpenSession` need a meter,
so they compile but do not run here; [dlms-sim](https://github.com/cB-Sigma/dlms-sim)
runs the same steps against its simulated meters.

A meter:

```go
import (
	"github.com/cB-Sigma/dlms/classes"
	"github.com/cB-Sigma/dlms/server"
)

s := &server.Server{SystemTitle: []byte("SGM00001")}
s.Add(&classes.Clock{LN: "0.0.1.0.0.255"},
	&classes.Register{LN: "1.0.32.7.0.255", Value: axdr.CreateAxdrLongUnsigned(23050), Scaler: -2, Unit: 35})
s.Associations = []*server.Association{
	{ClientAddress: 16},
	{ClientAddress: 48, Mechanism: 5, Policy: cosem.SecAuthentication | cosem.SecEncryption, Key: key, AuthKey: ak},
}
addr, err := s.ListenWrapper(":4059")
```

## Documentation

API reference: https://pkg.go.dev/github.com/cB-Sigma/dlms

| Package | What it does |
|---|---|
| `cosem` | The client: `SecurityConfig` (settings as text) and `Associate`/`Client` (AARQ/AARE, HLS mechanisms 2 to 7, the frame counter read through the public client); `SecureTransport` (suites 0 to 2, every ciphering form, general signing, the broadcast key, third-party layers, compression, ciphered release); `ICReservation`, `Counter` and `PushCounter` over an `iotsec.Store`; `SecuritySetup` (class 64); pushes (`OpenProtectedPush`, `MapPush`, `ServeHDLCPushes`, general block transfer); `InboundConn` (meter-initiated connections); `Gateway` (data concentrators); profile reading by range; `NewPortClient` over a port another protocol opened; serial lines with the IEC 62056-21 mode E opening; DLMS APDUs inside M-Bus (`Seal`, `Open`, `Request`, `Exchange`) |
| `server` | The meter side: `Server` with `Association`s per client address, `Add` objects, `ListenWrapper`, `ListenUDP`, `ListenHDLC`, `ServeWrapper`, `ServeHDLC`; `Push`, `PushTo`, `PushHDLC`; `Stats` |
| `classes` | The interface classes: `Lookup`/`All` (attributes, methods, short name offsets), the `Object` interface, typed objects (`Register`, `Clock`, `ProfileGeneric`, `DisconnectControl`, `ImageTransfer`, ...), `Generic`, object list encoding and parsing, COSEM date-times |
| `hdlc` | Frames, SNRM/UA negotiation, a client transport for gosem (`Client`), a server `Station`, a multi-drop `Bus`, a frame `Scanner` |
| `phy` | The physical layer over any `net.Conn`: PH services, Hayes modem procedures, the identification service, a simulated modem |
| `wrapper` | The wrapper header and a gosem transport over TCP or UDP |
| `gateway` | The gateway prefix for meters behind a data concentrator |
| `lpwan` | DLMS over NB-IoT (UDP reply windows, sleeping meters, a command queue) and LoRaWAN (a SCHC bridge to a `NetworkServer`, an in-memory `MemNS`), each meter as a `net.Conn` of wrapper frames |
| `iec6205621` | IEC 62056-21 sessions over serial ports or converters, programming mode, annex C, wake-ups, mode D, mode E; reduced-ID point names |
| `obis` | OBIS codes: parse (full, short and reduced forms), validate, ranges, what a standard code means with its classes, camel-case point names (`1.0.21.7.0.255` is `activePowerImportL1`) |
| `is15959` | IS 15959 Parts 1 to 3 as data under one point name per OBIS code; `EventInfo` |

## Testing

```
go test -race ./...
```

The tests use the worked examples of the standards (the IEC 62056-46
FCS table and frames, the IEC 62056-4-7 annex A.4 split, the IEC
62056-5-3:2023 Table 30 and annex E ciphering and release examples, the
Green Book's suite 0 example), RFC 3394 key wrap and NIST CAVS ECDSA
vectors, and fuzzing of the ciphered and general APDU decoders and of
IEC 62056-21 messages. Tests carry
`// Covers: SIG-...` comments: requirement IDs of the SigmaM2M project's
compliance report, which mean nothing else here.

The client's tests against a simulated meter (every mechanism, suite and
ciphering form, third-party layers, compression, data concentrators, the
LoRaWAN bridge, IEC 62056-21 sessions) are in
[dlms-sim](https://github.com/cB-Sigma/dlms-sim), so this module does not
depend on its simulator.

### Interop tested against

Against Gurux, written independently of this module, on 2026-10-11
(`interop/`, a nested test-only module that starts the peer in Docker;
`cd interop && SIGMA_DLMS_INTEROP=1 go test -v ./...`). Peer: the
server example of Gurux.DLMS.Java at commit 709c3a0 (gurux.dlms 4.0.95
from Maven Central), built in `maven:3.9.9-eclipse-temurin-17`: its
logical name servers (HDLC and wrapper) and its short name servers (HDLC
and wrapper); and Gurux's Python client against our `server`. The
server's own tests (`server/`) drive it with this module's client over
the wrapper on TCP and UDP and HDLC, every mechanism and suite included.

| Check (our client against the Gurux server) | Wrapper | HDLC |
|---|---|---|
| No security, public client: logical device name, invocation counter | pass | pass |
| Low-level security: clock, register with scaler and unit, data object | pass | pass |
| Low-level security with a wrong password: refused, reported as such | pass | |
| HLS mechanism 2 (Gurux's AES reading of it) | pass | |
| HLS mechanism 2 with authenticated and encrypted APDUs (suite 0) | pass | |
| HLS-GMAC, suite 0, authenticated and encrypted APDUs: clock, register, profile generic by range, the whole 10 002-row buffer in 942 blocks | pass | |
| HLS-GMAC with Gurux's default settings (no ciphering context, plain APDUs): our automatic context is refused with diagnostic 2; `applicationContext: "ln"` associates and reads clock, register and profile by range | | pass |
| Profile generic: the whole buffer (10 002 rows, 858 blocks) and by range | pass | pass |
| ACCESS: three gets in one request, with HLS mechanism 2 and with HLS-GMAC and authenticated and encrypted APDUs (ACCESS then in general-glo ciphering) | pass | |
| Security suite 1 (HLS-SHA256, authenticated and encrypted APDUs) | pass | |
| General-glo ciphering (general protection proposed) | pass | |
| A dedicated key: the association (HLS passes 3 and 4 under the global key) | pass | |
| Short name referencing against the Gurux short name server: object list, logical device name, clock, register, profile columns and the whole 10 002-row buffer in 847 data blocks, low-level security and HLS mechanism 2 | pass | pass |

| Check (Gurux's client, gurux-dlms 1.0.203 for Python in `python:3.12.10-slim`, against our `server`) | Wrapper | HDLC |
|---|---|---|
| No security, low-level, HLS mechanism 2, HLS-GMAC with authenticated and encrypted APDUs: clock, register, scaler and unit, a data object | pass | pass |
| Profile generic whole (in data blocks), by entry and by range; a 1 500-octet SET in data blocks; an ACTION | pass | pass |
| HLS-GMAC in security suites 0, 1 and 2, each in general-glo, general-ded, service-specific, and service-specific with a dedicated key ciphering (the server counted every form) | pass | suite 1 |
| Short names: object list, reads, a write, the profile whole, by entry and by range, with low-level security and HLS mechanism 2 | pass | pass |

Gurux's published unit-test vectors (Gurux.DLMS.Android at commit
d3489a4, fetched at run time, not kept here): the AES-GCM
authentication, encryption and authenticated encryption of a GET request
match `Protect` and `Unprotect`, the AES key wrap vectors match `WrapKey`
and `UnwrapKey`, and our ACCESS request encoder gives the octets of its
`accessRequestTest` (two gets, two sets of activity calendar values)
while `DecodeAccessResponse` reads its `accessResponseTest`.

These runs found and fixed: our HLS mechanism 2 challenge is one AES
block long (the form both the ECB and Gurux's CBC reading accept); the
application context is selectable for meters that take HLS-GMAC only
without the ciphering context; with a dedicated key, HLS passes 3 and 4
now go under the global key, as Gurux's server and client expect (the
association is not established until pass 4); short name data blocks are
asked for by the number of the block received. The Gurux Python client
against dlms-sim's meter is in
[dlms-sim](https://github.com/cB-Sigma/dlms-sim).

Not checked against another implementation, and why: Gurux's Java server
example answers requests ciphered under a dedicated key with exception
1/2, so reads under a dedicated key are checked only against Gurux's
client (our server) and dlms-sim; gurux-dlms 1.0.203 for Python fails in
its own code on a ciphered short name reply_to_HLS_authentication, on
short name data blocks and on receiving general block transfer
(AttributeError), so those paths are checked with our own client; Gurux's
server acknowledges ACCESS sets and actions without doing them; suite 2,
general ciphering with key agreement, general signing, third-party
protection and compression on our client are checked against dlms-sim
only (Gurux's example server has no such association). Not yet: a real
meter or data concentrator.


## Related repositories

- [dlms-sim](https://github.com/cB-Sigma/dlms-sim): simulated DLMS/COSEM
  meters (also served by this module's `server`), a data concentrator and
  an IEC 62056-21 meter.
- [mbus](https://github.com/cB-Sigma/mbus): wired and wireless M-Bus,
  which carries DLMS APDUs with this module's `cosem`.
- [schc](https://github.com/cB-Sigma/schc): SCHC and V.44, used for
  LoRaWAN and compression.
- [iotsec](https://github.com/cB-Sigma/iotsec): the store and crypto
  policy seams.

## Status

v0.x: the API may change before v1.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability privately.

## Licence

Apache-2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). Copyright 2026
Abhinav Gautam.
