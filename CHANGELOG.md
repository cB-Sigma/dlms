# Changelog

## v0.2.0 (2026-10-11)

Added

- `server`: the meter side as a library. Associations per client address
  with no security, low-level security or HLS mechanisms 2 to 7, security
  suites 0 to 2, authenticated, encrypted or both, global and dedicated
  keys, service-specific, general-glo and general-ded ciphering, the
  broadcast key, invocation counter checks, ciphered release and
  unconfirmed associations; GET, SET and ACTION normal, with list and in
  data blocks both ways; ACCESS; short name read, write and unconfirmed
  write with parameterized access and data blocks; general block
  transfer; access rights per association; the current association
  object (LN or SN) with its object list; data-notification pushes to
  TCP, UDP and HDLC links and from a push setup; the wrapper over TCP and
  UDP and HDLC; `Stats`.
- `classes`: 40 COSEM interface classes as data (attributes, methods,
  short name offsets) and 25 as Go types implementing `classes.Object`
  (data, registers, profile generic, clock, script table, schedule,
  special days, associations, SAP assignment, image transfer, activity
  calendar, register monitor, single action schedule, port setups, push
  setup, security setup, disconnect control, limiter, ...), `Generic` for
  the others, object list encoding and parsing.
- `cosem`: the ACCESS service (`Client.Access`, `Association.Access`,
  `AccessRequest`, `AccessResponse`); short name referencing
  (`SecurityConfig.Referencing`, application contexts `sn` and
  `sn-ciphering`, `Association.ReadSN`, `WriteSN`, `ActionSN`, `GetSN`,
  `SetSN`, `BaseName`, `ReadObjectListSN`; `Client.Get` reads through base
  names on a short name association); `Association.Exchange` and
  `SecureTransport.Exchange` for raw APDUs under the association's
  protection; the conformance block bits (`Conformance*`) and
  `ClientConfig.Conformance`/`AssociationConfig.Conformance`; exported
  `HLS.Answer` and `HLS.Check` (either side of passes 3 and 4);
  `SNMethodOffset`; image transfer as a state machine (`Client.TransferImage`:
  resume, resend of missing blocks, verify, activate).
- `interop/`: our client against Gurux's short name servers, ACCESS,
  suite 1 and general-glo against Gurux's server; Gurux's Python client
  against our server (logical and short names, suites 0 to 2, every
  ciphering form); Gurux's ACCESS vectors.

Changed

- The client proposes the ACCESS service in its conformance block.
- With a dedicated key, HLS passes 3 and 4 are protected with the global
  key (the dedicated key serves the established association), as Gurux's
  server and client expect (our server and dlms-sim's meter accept
  either).

Still open

- Key rotation as a client state machine; HDLC modulo
  128; sending segmented UI frames; the IS 15959 special days table; on
  the server, general ciphering with key agreement, general signing,
  third-party protection and compression; short name writes in data
  blocks on the client.

## v0.1.0 (2026-10-11)

First release: the client, HDLC, the physical layer, the wrapper, the
gateway prefix, NB-IoT and LoRaWAN, IEC 62056-21, OBIS and the IS 15959
catalogue.
