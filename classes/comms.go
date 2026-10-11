// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package classes

import (
	"sync"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
)

// SAPEntry is one logical device of a SAP assignment: its address and
// its name (an octet string, usually printable text).
type SAPEntry struct {
	SAP  uint16
	Name []byte
}

func sapEntryOf(d *axdr.DlmsData) (SAPEntry, error) {
	it, err := structItems(d, 2)
	if err != nil {
		return SAPEntry{}, err
	}
	var e SAPEntry
	if e.SAP, err = u16Of(it[0]); err != nil {
		return e, err
	}
	e.Name, err = octetsOf(it[1])
	return e, err
}

// SAPAssignment is class 17: the logical devices of a physical device.
// connect_logical_device (1) adds or renames one by SAP, and removes it
// when the name is empty.
type SAPAssignment struct {
	sync.Mutex
	LN   string
	List []SAPEntry
}

func (o *SAPAssignment) ClassID() uint16     { return 17 }
func (o *SAPAssignment) Version() uint8      { return 0 }
func (o *SAPAssignment) LogicalName() string { return o.LN }

func (o *SAPAssignment) attrs() map[int8]attr {
	return map[int8]attr{2: readOnly(attr{get: func() (*axdr.DlmsData, error) {
		items := make([]*axdr.DlmsData, len(o.List))
		for i, e := range o.List {
			items[i] = structOf(axdr.CreateAxdrLongUnsigned(e.SAP), octetData(e.Name))
		}
		return arrayOf(items), nil
	}})}
}

func (o *SAPAssignment) Get(a int8, sel *Selector) (*axdr.DlmsData, error) {
	o.Lock()
	defer o.Unlock()
	return getAttr(o.LN, o.attrs(), a, sel)
}

func (o *SAPAssignment) Set(a int8, v *axdr.DlmsData, sel *Selector) error {
	o.Lock()
	defer o.Unlock()
	return setAttr(o.attrs(), a, v, sel)
}

func (o *SAPAssignment) Action(m int8, p *axdr.DlmsData) (*axdr.DlmsData, error) {
	if m != 1 {
		return nil, ObjectUndefined
	}
	e, err := sapEntryOf(p)
	if err != nil {
		return nil, err
	}
	o.Lock()
	defer o.Unlock()
	for i := range o.List {
		if o.List[i].SAP == e.SAP {
			if len(e.Name) == 0 {
				o.List = append(o.List[:i:i], o.List[i+1:]...)
			} else {
				o.List[i] = e
			}
			return nil, nil
		}
	}
	if len(e.Name) > 0 {
		o.List = append(o.List, e)
	}
	return nil, nil
}

// IECLocalPortSetup is class 19 (version 1): the optical or serial port
// of IEC 62056-21. Modes and baud rates are the class's enumerations.
type IECLocalPortSetup struct {
	sync.Mutex
	LN            string
	DefaultMode   uint8
	DefaultBaud   uint8
	ProposedBaud  uint8
	ResponseTime  uint8
	DeviceAddress []byte
	PasswordP1    []byte
	PasswordP2    []byte
	PasswordW5    []byte
}

func (o *IECLocalPortSetup) ClassID() uint16     { return 19 }
func (o *IECLocalPortSetup) Version() uint8      { return 1 }
func (o *IECLocalPortSetup) LogicalName() string { return o.LN }

func (o *IECLocalPortSetup) attrs() map[int8]attr {
	return map[int8]attr{2: fEnum(&o.DefaultMode), 3: fEnum(&o.DefaultBaud), 4: fEnum(&o.ProposedBaud),
		5: fEnum(&o.ResponseTime), 6: fOctets(&o.DeviceAddress), 7: fOctets(&o.PasswordP1),
		8: fOctets(&o.PasswordP2), 9: fOctets(&o.PasswordW5)}
}

func (o *IECLocalPortSetup) Get(a int8, sel *Selector) (*axdr.DlmsData, error) {
	o.Lock()
	defer o.Unlock()
	return getAttr(o.LN, o.attrs(), a, sel)
}

func (o *IECLocalPortSetup) Set(a int8, v *axdr.DlmsData, sel *Selector) error {
	o.Lock()
	defer o.Unlock()
	return setAttr(o.attrs(), a, v, sel)
}

func (o *IECLocalPortSetup) Action(m int8, p *axdr.DlmsData) (*axdr.DlmsData, error) {
	return noMethod(m, p)
}

// IECHDLCSetup is class 23 (version 1): the HDLC parameters of a port.
type IECHDLCSetup struct {
	sync.Mutex
	LN                string
	CommSpeed         uint8
	WindowTransmit    uint8
	WindowReceive     uint8
	MaxInfoTransmit   uint16
	MaxInfoReceive    uint16
	InterOctetTimeout uint16 // milliseconds
	InactivityTimeout uint16 // seconds
	DeviceAddress     uint16
}

func (o *IECHDLCSetup) ClassID() uint16     { return 23 }
func (o *IECHDLCSetup) Version() uint8      { return 1 }
func (o *IECHDLCSetup) LogicalName() string { return o.LN }

func (o *IECHDLCSetup) attrs() map[int8]attr {
	return map[int8]attr{2: fEnum(&o.CommSpeed), 3: fU8(&o.WindowTransmit), 4: fU8(&o.WindowReceive),
		5: fU16(&o.MaxInfoTransmit), 6: fU16(&o.MaxInfoReceive), 7: fU16(&o.InterOctetTimeout),
		8: fU16(&o.InactivityTimeout), 9: fU16(&o.DeviceAddress)}
}

func (o *IECHDLCSetup) Get(a int8, sel *Selector) (*axdr.DlmsData, error) {
	o.Lock()
	defer o.Unlock()
	return getAttr(o.LN, o.attrs(), a, sel)
}

func (o *IECHDLCSetup) Set(a int8, v *axdr.DlmsData, sel *Selector) error {
	o.Lock()
	defer o.Unlock()
	return setAttr(o.attrs(), a, v, sel)
}

func (o *IECHDLCSetup) Action(m int8, p *axdr.DlmsData) (*axdr.DlmsData, error) {
	return noMethod(m, p)
}

// TCPUDPSetup is class 41.
type TCPUDPSetup struct {
	sync.Mutex
	LN                string
	Port              uint16
	IPReference       string
	MSS               uint16
	MaxConnections    uint8
	InactivityTimeout uint16 // seconds
}

func (o *TCPUDPSetup) ClassID() uint16     { return 41 }
func (o *TCPUDPSetup) Version() uint8      { return 0 }
func (o *TCPUDPSetup) LogicalName() string { return o.LN }

func (o *TCPUDPSetup) attrs() map[int8]attr {
	return map[int8]attr{2: fU16(&o.Port), 3: fLN(&o.IPReference), 4: fU16(&o.MSS),
		5: fU8(&o.MaxConnections), 6: fU16(&o.InactivityTimeout)}
}

func (o *TCPUDPSetup) Get(a int8, sel *Selector) (*axdr.DlmsData, error) {
	o.Lock()
	defer o.Unlock()
	return getAttr(o.LN, o.attrs(), a, sel)
}

func (o *TCPUDPSetup) Set(a int8, v *axdr.DlmsData, sel *Selector) error {
	o.Lock()
	defer o.Unlock()
	return setAttr(o.attrs(), a, v, sel)
}

func (o *TCPUDPSetup) Action(m int8, p *axdr.DlmsData) (*axdr.DlmsData, error) {
	return noMethod(m, p)
}

// IPv4Setup is class 42. Addresses are 32-bit numbers, most significant
// octet first (192.0.2.1 is 0xC0000201). IPOptions is kept as A-XDR data.
type IPv4Setup struct {
	sync.Mutex
	LN                string
	DataLinkReference string
	IPAddress         uint32
	Multicast         []uint32
	IPOptions         *axdr.DlmsData
	SubnetMask        uint32
	Gateway           uint32
	UseDHCP           bool
	PrimaryDNS        uint32
	SecondaryDNS      uint32
}

func (o *IPv4Setup) ClassID() uint16     { return 42 }
func (o *IPv4Setup) Version() uint8      { return 0 }
func (o *IPv4Setup) LogicalName() string { return o.LN }

func (o *IPv4Setup) attrs() map[int8]attr {
	return map[int8]attr{2: fLN(&o.DataLinkReference), 3: fU32(&o.IPAddress),
		4: {get: func() (*axdr.DlmsData, error) {
			items := make([]*axdr.DlmsData, len(o.Multicast))
			for i, a := range o.Multicast {
				items[i] = axdr.CreateAxdrDoubleLongUnsigned(a)
			}
			return arrayOf(items), nil
		}, set: func(d *axdr.DlmsData) error {
			it, err := arrayItems(d)
			if err != nil {
				return err
			}
			out := make([]uint32, len(it))
			for i, x := range it {
				if out[i], err = u32Of(x); err != nil {
					return err
				}
			}
			o.Multicast = out
			return nil
		}},
		5: fArray(&o.IPOptions), 6: fU32(&o.SubnetMask), 7: fU32(&o.Gateway), 8: fBool(&o.UseDHCP),
		9: fU32(&o.PrimaryDNS), 10: fU32(&o.SecondaryDNS)}
}

func (o *IPv4Setup) Get(a int8, sel *Selector) (*axdr.DlmsData, error) {
	o.Lock()
	defer o.Unlock()
	return getAttr(o.LN, o.attrs(), a, sel)
}

func (o *IPv4Setup) Set(a int8, v *axdr.DlmsData, sel *Selector) error {
	o.Lock()
	defer o.Unlock()
	return setAttr(o.attrs(), a, v, sel)
}

// Action adds (1) or deletes (2) a multicast address and returns the
// number of them (3).
func (o *IPv4Setup) Action(m int8, p *axdr.DlmsData) (*axdr.DlmsData, error) {
	o.Lock()
	defer o.Unlock()
	switch m {
	case 1, 2:
		a, err := u32Of(p)
		if err != nil {
			return nil, err
		}
		var keep []uint32
		for _, x := range o.Multicast {
			if x != a {
				keep = append(keep, x)
			}
		}
		if m == 1 {
			keep = append(keep, a)
		}
		o.Multicast = keep
		return nil, nil
	case 3:
		return axdr.CreateAxdrLongUnsigned(uint16(len(o.Multicast))), nil
	}
	return nil, ObjectUndefined
}

// PushDestination is where and how a push goes: the transport service and
// message type are the class's enumerations, Address the destination
// (for TCP, "host:port" as octets).
type PushDestination struct {
	Transport uint8
	Address   []byte
	Message   uint8
}

// PushSetup is class 40 (version 0). push (1) reads the push object list
// through the server and hands the values to OnPush, which sends them.
// CommunicationWindow is kept as A-XDR data (an array of {start, end}).
type PushSetup struct {
	sync.Mutex
	LN                         string
	PushObjectList             []CaptureObject
	Destination                PushDestination
	CommunicationWindow        *axdr.DlmsData
	RandomisationStartInterval uint16 // seconds
	NumberOfRetries            uint8
	RepetitionDelay            uint16 // seconds
	OnPush                     func(values []*axdr.DlmsData) error

	resolver Resolver
}

func (o *PushSetup) ClassID() uint16     { return 40 }
func (o *PushSetup) Version() uint8      { return 0 }
func (o *PushSetup) LogicalName() string { return o.LN }

// Bind keeps the server's resolver for pushes.
func (o *PushSetup) Bind(r Resolver) {
	o.Lock()
	o.resolver = r
	o.Unlock()
}

func (o *PushSetup) attrs() map[int8]attr {
	return map[int8]attr{
		2: {get: func() (*axdr.DlmsData, error) { return captureListData(o.PushObjectList), nil },
			set: func(d *axdr.DlmsData) error {
				l, err := captureListOf(d)
				if err == nil {
					o.PushObjectList = l
				}
				return err
			}},
		3: {get: func() (*axdr.DlmsData, error) {
			return structOf(axdr.CreateAxdrEnum(o.Destination.Transport), octetData(o.Destination.Address),
				axdr.CreateAxdrEnum(o.Destination.Message)), nil
		}, set: func(d *axdr.DlmsData) error {
			it, err := structItems(d, 3)
			if err != nil {
				return err
			}
			var pd PushDestination
			if pd.Transport, err = enumOf(it[0]); err != nil {
				return err
			}
			if pd.Address, err = octetsOf(it[1]); err != nil {
				return err
			}
			if pd.Message, err = enumOf(it[2]); err != nil {
				return err
			}
			o.Destination = pd
			return nil
		}},
		4: fArray(&o.CommunicationWindow),
		5: fU16(&o.RandomisationStartInterval),
		6: fU8(&o.NumberOfRetries),
		7: fU16(&o.RepetitionDelay),
	}
}

func (o *PushSetup) Get(a int8, sel *Selector) (*axdr.DlmsData, error) {
	o.Lock()
	defer o.Unlock()
	return getAttr(o.LN, o.attrs(), a, sel)
}

func (o *PushSetup) Set(a int8, v *axdr.DlmsData, sel *Selector) error {
	o.Lock()
	defer o.Unlock()
	return setAttr(o.attrs(), a, v, sel)
}

// Values reads the push object list through the server.
func (o *PushSetup) Values() ([]*axdr.DlmsData, error) {
	o.Lock()
	r := o.resolver
	list := append([]CaptureObject(nil), o.PushObjectList...)
	o.Unlock()
	if r == nil {
		return nil, TemporaryFailure
	}
	out := make([]*axdr.DlmsData, len(list))
	for i, c := range list {
		v, err := resolveCapture(r, c)
		if err != nil {
			return nil, err
		}
		out[i] = v
	}
	return out, nil
}

// Action runs push (1).
func (o *PushSetup) Action(m int8, _ *axdr.DlmsData) (*axdr.DlmsData, error) {
	if m != 1 {
		return nil, ObjectUndefined
	}
	o.Lock()
	f := o.OnPush
	o.Unlock()
	if f == nil {
		return nil, TemporaryFailure
	}
	vals, err := o.Values()
	if err != nil {
		return nil, err
	}
	return nil, f(vals)
}
