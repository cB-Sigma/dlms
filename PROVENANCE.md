# Provenance

## How the code was written

Written for SigmaM2M in Go from the standards below. No code was ported
or copied from another implementation. The repository's history records
no porting from Gurux (GuruxDLMS.c, .Net, Java or Python), OpenMUC
jDLMS, dlms-cosem or any other DLMS stack, and a search of this module
for their names, comments, identifiers and porting markers finds none.
The application layer encoders the module uses come from
gitlab.com/circutor-library/gosem (MIT) as a dependency; none of its
code is copied in. The HDLC, wrapper, gateway and physical layers here
are our own and replace gosem's own transports in SigmaM2M. The security
layer of `cosem` (SecureTransport) is our own too: gosem runs without
ciphering and sees only plain APDUs.

`cosem`, `iec6205621` and `lpwan` came from SigmaM2M's DLMS/COSEM and
IEC 62056-21 adapters in stage 2 of the split (2026-10-06), with the
parts that write to SigmaM2M's resource tree, read its settings or keep
its state left there. The same search for other stacks' names,
identifiers and porting markers over these packages finds none.

The simulators (the meter, the data concentrator and the IEC 62056-21
meter) were written with the client and moved into the separate
dlms-sim module on 2026-10-11, with the tests that drive them, so this
module does not depend on them.

Facts are not code: frame layouts, field values, reserved addresses,
OBIS codes, class identifiers and check sequences are what any
implementation must use, and our code around them is our own design. The
HDLC frame check table, for example, is computed at start-up from the
polynomial rather than written out. No specification text is reproduced;
comments cite clause, table and figure numbers in our own words.

## Standards followed

(`server` and `classes`, added in v0.2.0: IEC 62056-5-3:2023 and IEC
62056-6-2:2023, as `cosem`; see "Added in v0.2.0".)

All are licensed or (for the BIS standards) free copies read in place.
None is kept in the repository or redistributed.

| Package | Followed |
|---|---|
| `hdlc` | IEC 62056-46 Edition 1.1 (2002 with Amendment 1:2006; consolidated 2007-02): frame format type 3, addressing and reserved addresses, control fields, SNRM/UA parameter negotiation, segmentation, windows, UI frames, exception recovery, time-outs, the annex A FCS. ISO/IEC 13239:2002 (third edition): the frame format field, the mode-setting information field and its user data subfield, the FRMR information field. IEC 62056-7-6 Edition 1.0 (2013-05): the HDLC-based profile (addressing of physical and logical devices, unconfirmed services in UI frames, event notification at the right to talk, multi-drop) |
| `phy` | IEC 62056-42 Edition 1.0 (2002-02): PH-CONNECT, PH-ABORT and PH-DATA, the identification service, the annex A Hayes modem procedures |
| `wrapper` | IEC 62056-4-7 Edition 1.0 (2015-05): the wrapper header, reserved wPorts, the TCP and UDP transport layers, the annex A.4 example. IEC 62056-9-7 Edition 1.0 (2013-04): the TCP-UDP/IP profile (port 4059, complete APDUs) |
| `gateway` | IEC 62056-5-3:2023 (Edition 4.0) annex C: the gateway prefix (E6/E7 header, network ID, physical device address) |
| `obis` | IEC 62056-6-1:2023 (Edition 4.0, 2023-12; EN IEC 62056-6-1:2024 adopts it unchanged): value group structure, the manufacturer, reserved, utility, consortia and country ranges, media, the abstract and electricity codes, the standard object codes, the reduced ID codes of annex A. IEC 62056-6-2:2023 (Edition 4.0) clause 6: which interface classes each COSEM object has. EN 13757-1:2021 clause 11: media 4 to 9 (heat cost allocators, cooling, heat, gas, cold and hot water) |
| `is15959` | IS 15959 (Part 1):2011, reaffirmed 2016; IS 15959 (Part 2):2016 with Amendment 1 (April 2017) and Amendment 2 (May 2017), reaffirmed 2021; IS 15959 (Part 3):2017. IS 16444 (Part 1):2015 and (Part 2):2017 for the event classification (`EventInfo`), which is our own (see below). IEC 62056-6-2:2023 for the interface classes the catalogue names |
| `cosem` | IEC 62056-5-3:2023 (Edition 4.0): ACSE and xDLMS services, the authentication mechanisms, security suites, the security control byte, service-specific and general ciphering, general signing, key agreement (the annex on ECDH key agreement), compression (5.3.6), third-party protection, the ciphered release (6.3, annex E), the gateway (annex C). The DLMS UA Green Book for the same and the security setup class. IEC 62056-6-2:2023: the interface classes read and the security setup (class 64), profile generic (class 7), push setup (class 40), limiter (class 71) and clock attributes. EN 13757-1:2021 9.2 and 10.3.2: DLMS inside M-Bus, tunnelled M-Bus frames, the general error object. RFC 3394 (key wrap), NIST SP 800-56A (the concatenation KDF) |
| `lpwan` | RFC 8724 and RFC 9011 (SCHC and its LoRaWAN profile, through libs/schc), the LoRa Alliance Regional Parameters RP002-1.0.x as we read them (F-2104); the DLMS UA LoRaWAN profile is not available (F-2100), so its choices are settings |
| `iec6205621` | IEC 62056-21 Edition 1.0 (2002-05): clause 6 (messages, modes A to E, programming mode, partial blocks), annexes A (flow), B (wake-up), C (formatted codes), D (access levels) and E (mode E) |

## The OBIS data (obis/obis.yaml)

`obis.yaml` was transcribed by hand, in SigmaM2M, from licensed copies of
IEC 62056-6-1:2023, IEC 62056-6-2:2023 clause 6 and EN 13757-1:2021
clause 11. What it holds:

- facts: value group numbers and ranges, which range a value is in,
  country codes with their country names, the standard object codes and
  the interface class identifiers each object may have, and the clause
  or table each row comes from;
- our own wording: every `key` and `name` is a camel-case point name
  SigmaM2M derives, and every `label` is a short description written for
  a person reading a point's description. The file's header says so.

**Flag for the reviewer's pass.** The `label` values of the gas (A = 7)
value group D tables, and of some of the electricity C and D tables, are
long systematic descriptions such as "maximum index difference over
measurement period 1 in Bp2, at base conditions". They are names of
codes, built from the same parts as the standard's own table rows, and
some may match the standard's row descriptions word for word. I could not
compare them with the text (the standard is not in this workspace). A
reviewer with EN 13757-1:2021 Tables 30 to 40 and IEC 62056-6-1:2023
Tables 13 to 19 should compare them, and reword any that are verbatim
(the names, which the code uses, would not change).

## The IS 15959 catalogue (is15959/)

The catalogue is Go data (`part1.go`, `part2.go`, `part3.go`,
`events.go`, `names.go`, `kinds.go`), transcribed by hand from the BIS
standards. What it holds:

- facts: OBIS codes, interface classes, attribute and method numbers,
  units, access rights per association, profile capture objects and
  periods, event codes and which log carries them, ESW bit numbers, push
  setups, client addresses and authentication and security levels of the
  associations, each with its part, clause and table reference;
- our own wording: point names (`names.go`), profile titles, the short
  event names of `eventNames`, the event keys, categories and the
  occurrence/restoration pairing and tamper class of `EventInfo` (our own
  classification; SigmaM2M finding F-1921 records that neither IS 15959
  nor IS 16444 says which codes are tampers), and the A-XDR types of `kinds.go`, which the standards mostly
  leave open and which only the simulator relies on.

**Flag for the reviewer's pass.** The event names in `events.go` ("R-phase
voltage missing", "over-voltage cleared", ...) are short labels for event
codes and say what each code means in a few words. The standard's
annex tables describe the same events in a few words too, so some names
may be close to its wording. They are identifiers rather than prose, but
a reviewer with IS 15959 Part 1 annex G (Tables 32 to 38) should compare
them.

Where the standards conflict with each other or are ambiguous, the code
follows a reading recorded as a SigmaM2M finding (F-155 to F-168, F-175,
F-176 for IS 15959; F-260, F-261 and F-265 for IS 15959 against
IEC 62056-6-1). The `F-nnnn` numbers in comments and data refer to that
project's register of specification findings; each comment says, in our
words, which reading the code takes, so the code reads on its own.

IS 15959 is a Bureau of Indian Standards publication. The catalogue holds
its facts (codes, classes, attributes, rights, units, table and clause
numbers) and short identifiers of our own; it reproduces no clause text
and no table of text.

## Test data

- Worked examples and test values of the standards, used as facts: the
  IEC 62056-46 annex A FCS values and the 6.4.2.3 address example, the
  ISO/IEC 13239 frame and field layouts, the IEC 62056-4-7 annex A.4 WPDU
  split across TCP reads, the IEC 62056-5-3:2023 annex E.7 ciphered
  release request and its keys (example keys of the standard, not keys
  of any meter), the IEC 62056-6-1:2023 and EN 13757-1:2021 examples and
  annex A minimum objects.
- RFC 3394 section 4 key wrap examples; NIST CAVS 11.0 ECDSA SigVer
  vectors (public domain) for P-256/SHA-256 and P-384/SHA-384.
- The tests carry `// Covers: SIG-...` comments: SigmaM2M requirement IDs
  that its compliance report collects. They mean nothing else here.

## Added in v0.2.0

- `server` (the meter side), `classes` (the interface classes as data and
  Go types), the ACCESS service (`cosem/access.go`) and short name
  referencing (`cosem/sn.go`) were written in October 2026 from IEC
  62056-5-3:2023 (ACCESS 7.3.8, short names 7.4, the association and
  block transfer clauses, general block transfer) and IEC 62056-6-2:2023
  (class, attribute and method numbers, short name offsets). The server's
  APDU protection and HLS answers are cosem's own functions; its session
  logic follows the same reading of the standard as dlms-sim's meter,
  which was written separately.
- Gurux's sources (GPL-2.0) were read, not copied, at the pinned commits
  named in `interop/`, for interoperability facts only: the octet layout
  of an ACCESS response (Gurux leaves out the optional copy of the
  request's specifications and writes an empty date-time), that its short
  name server takes reply_to_HLS_authentication as a write and answers
  with a read response, that it acknowledges short name data blocks with
  the number of the block received, that its clients protect HLS passes 3
  and 4 with the global key when a dedicated key was agreed, and its table
  of the short name offsets of method 1 per class (numbers, which we
  checked against the class descriptions). No Gurux code, comment or
  identifier is in this module; the interop tests fetch Gurux at test
  time and keep nothing.
- The `classes` catalogue holds class identifiers, versions, attribute
  and method numbers and short name offsets as facts; the names are our
  own camel-case or plain words. Classes whose attribute lists we were not
  sure of were left out (Account 111, Charge 113, M-Bus slave port setup
  25); the disconnect control state transitions per control mode, push
  setup (listed as version 0) and GSM diagnostic (version 1) are flagged
  in their doc comments for a check against the standard.

## Words in errors and events

Some error texts name the settings SigmaM2M spells them with
(`acceptUnauthenticatedPush`, `meterSystemTitle`, `broadcastKey`,
`compression.enabled`), and push refusals carry event names of SigmaM2M's
security log (`dlms_push_unauthenticated_refused`,
`dlms_push_system_title_refused`). They were kept so that SigmaM2M's
messages did not change; an application may map them.

## Not checked

- A line-by-line comparison with Gurux or other DLMS stacks. None was
  needed on the evidence above (no porting record, no shared identifiers
  or comments), and the Gurux sources are not kept in this workspace
  (v0.2.0 read some of them at test time, see above).
- The two flags above (OBIS labels, IS 15959 event names) need a reviewer
  with the standards.
