# Changelog

## v0.3.0 (2026-10-11)

Backwards compatible with v0.2.0.

Added

- `server`: general ciphering on the meter side, with every key-info
  (identified, wrapped under `Association.MasterKey`, one-pass and static
  agreed keys with `KAKey` and `ClientKAKey`): requests are opened and
  answered under a fresh key of the kind the request used, with its
  transaction-id; general signing (`Association.Signing` requires it, a
  signed request is answered signed with `SigningKey` either way); V.44
  compression (`Association.Compression`, `CompressAnswers`) in
  general-glo, general-ded and general ciphering; third-party layers
  (`Association.ThirdParties`: a third party's general-signing and
  agreed-key general-ciphering inside the client's protection, answered
  with the server's layers for it, or an unprotected layer as in annex
  J.3); `Stats` counts general ciphering, signed requests, refused
  signatures, third-party requests and compressed requests.
- `server`: `Server.NewSession` and `Session.Handle` for callers that
  carry APDUs themselves.
- `cosem`: `Responder`, the server side of general ciphering, signing,
  third parties and compression, sharing the client's code
  (`OpenGeneral`, `SealGeneral`, `OpenGloDed`, `SealGloDed`, `OpenSigned`,
  `Sign`, `OpenThirdParty`, `AnswerThirdParty`); `Compression.Params`.
- `concentrator`: a data concentrator (DCU) in gateway mode (annex C
  prefix, routing by network ID and physical address) and logical-device
  mode (by server SAP) on one head-end connection; meters in the process
  (`Local`, `LogicalDevice`), over any gosem transport (`Transport`: HDLC,
  wrapper, NB-IoT) or anything implementing `Downstream`; a session per
  meter, client and server SAP, each running on its own; pushes forwarded
  (`Forward`, `ForwardTo`); `ResponsePrefix` for concentrators that name
  themselves; `Stats`.
- `iec6205621/meter`: the meter side of IEC 62056-21 (modes A to E,
  programming mode, partial blocks, annex C formatted codes, annex B
  wake-ups, mode D pushes, several meters on one line), with mode E
  handing the line to any `ModeE` such as a `server.Server`. Moved here
  from dlms-sim, whose `iec6205621sim` now aliases it.
- `is15959/meter`: an IS 15959 meter builder. `New` gives a
  `server.Server` with every object, profile, event log and push setup of
  a profile, values a household meter could show, profiles that agree
  with the registers, the profile's associations with their keys and
  access rights, disconnect control that logs its events, the billing
  script; `Populate`, `Recapture`, `RaiseEvent`, `Row` fill any `Store`.
  Moved from dlms-sim, whose IS 15959 meter now uses it.
- `lpwan/enddevice`: the meter end of DLMS over LoRaWAN (SCHC with
  ACK-on-Error uplinks, ACK-Always downlinks, class A polling, pushes) and
  NB-IoT (power saving mode wakes with a push, active time), serving a
  `server.Server` (`ServerHandler`) or any `Handler` over any `Radio`
  (`MemRadio` for `lpwan.MemNS`). Moved from dlms-sim, whose LoRaWAN and
  NB-IoT meters now use it.
- Found with Gurux's client through the concentrator: gurux-dlms 1.0.203
  for Python prefixes the AARQ but leaves the prefix off its ciphered
  APDUs, and ciphers the prefix with the APDU instead. The concentrator
  routes an unprefixed request to the meter the same client and server
  SAPs last reached with the prefix (answered without one; `Strict`
  turns this off), and the server takes a gateway prefix found inside the
  protection and answers with one the same way. Annex C keeps the prefix
  outside the protection; both are accepted.
- `hdlc`: modulo 128 numbering (ISO/IEC 13239 extended control field,
  SNRME, windows up to 127) for 13239 peers: `Modulo8`, `Modulo128`,
  `MaxWindow128`, `KindSNRME`, `ParseControlModulo`, `Control.Encode`,
  `Frame.Extended`, `Frame.Control2`, `Frame.ControlField`,
  `DecodeModulo`, `Params.CheckModulo`; `Config.Modulo` (with
  `ModuloFallback` to modulo 8 when the peer refuses) and
  `Station.Modulo128`; FRMR in the modulo 128 layout. Sending segmented
  UI frames: `Config.SegmentUI` (client broadcasts) and
  `Station.SegmentUI`. IEC 62056-46 itself uses modulo 8 and forbids
  segmented UI frames, so both stay off by default.
- `cosem`: key rotation as a client state machine (`KeyRotation` with
  `Rotate`, `Resume`, `Status`; `RotateByTransfer`, `RotateByAgreement`;
  states idle, prepared, invoked, done, rolled back, unconfirmed): new
  keys are stored first, wrapped under a storage key in an
  `iotsec.Store`, sent under the current master key, then checked by a new
  association (a master key change by re-sending the authentication key
  under the new one); on failure the old keys are tried and the record is
  rolled back, or it stays unconfirmed for `Resume` after a crash.
  `ClientRotationLink` drives a `Client`.
- `is15959`: the special days table (0.0.11.0.0.255, class 11) in the
  Part 2 and Part 3 profiles with the activity calendar's rights, and the
  `special-days`, `special-day-insert` and `special-day-delete` commands.
  No IS 15959 table lists it, so the entry and its rights are our reading
  (its `Ref` says so); Part 1 profiles do not get it.
- `interop/`: Gurux's Python client through our data concentrator
  (gateway and logical-device modes, a meter in process and one over
  HDLC) and against an IS 15959 meter built by `is15959/meter`.

Changed

- `classes.DisconnectControl`: control mode 6's remote reconnect now
  arms (ready for reconnection) as in modes 1, 3 and 5, and mode 7 is
  accepted (remote reconnect closes from disconnected and from ready,
  local reconnect allowed, manual disconnect not). Checked against the
  grouping of modes in Gurux's control mode enumerations (Python and
  .Net); which group arms and which closes is our reading. Gurux's
  libraries give class 70 version 1; ours stays 0 (to check against
  IEC 62056-6-2).
- `classes` catalogue: push setup (40) stays version 0 and GSM
  diagnostic (47) version 1, checked against Gurux's attribute counts;
  the doc comments that flagged them now say what was checked.
- The IS 15959 meter's instantaneous registers read like a household
  load on a 230 V, 50 Hz supply.

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
