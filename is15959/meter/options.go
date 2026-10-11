// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package meter builds an IS 15959 meter from a profile of package
// is15959: every object, profile, event log and push setup of the profile
// with values a meter of that kind could show, the associations the
// profile defines (public client, meter reader, utility settings,
// firmware, push, in-home display) with their keys and access rights, and
// the methods that act on the meter (disconnect control with its events,
// the billing script, image transfer, event logs).
//
// New returns the meter on package server, ready to serve over the wrapper
// or HDLC. The value generation works on a Store, so another meter model
// (dlms-sim's simulated meter uses it) can be filled the same way:
// Populate, Recapture, RaiseEvent, Row.
//
// Values are made up, not measured: registers get plausible readings for
// a household meter of the profile's category, profiles get entries that
// agree with the instantaneous registers (a block's energy is the measured
// power over the block, a daily row's cumulative energy runs up to the
// register), event logs get one entry per event code.
package meter

import (
	"bytes"
	"encoding/binary"
	"strings"
	"time"

	"github.com/cB-Sigma/dlms/is15959"
)

// Keys are one association's global keys (16 octets each, suite 0).
type Keys struct {
	Key, AuthKey []byte
}

// Options configure a meter. Zero fields take the defaults given.
type Options struct {
	Serial      string // meter serial number (default "00000001")
	Flag        string // manufacturer FLAG ID, 3 letters (default "SGM")
	Password    string // meter reader low-level secret (default "ABCDEFGH")
	HLSSecret   string // utility settings HLS secret, mechanism 2 (default "UTILITYSECRET016")
	FWSecret    string // firmware association HLS secret (default "FIRMWARESECRET16")
	HLSKeys     Keys   // global keys (utility settings, firmware; default for the others)
	ReaderKeys  Keys   // meter reader global keys (default HLSKeys)
	PushKeys    Keys   // push association global keys (default HLSKeys)
	IHDKeys     Keys   // the in-home display association's own keys
	SystemTitle []byte // the meter's (default FLAG followed by 5 octets of the serial)
	Rows        int    // entries per profile and event log (default 4)
	Now         time.Time
	// Location is the meter clock's zone (default Asia/Kolkata, or a fixed
	// +05:30 where the zone database is missing).
	Location *time.Location
	// Firmware, Category and Rating are nameplate values (defaults
	// "SIM-1.4.2", "C1", "10-60A"); Model is the manufacturer's name
	// object (default "SIGMA SIM").
	Firmware, Category, Rating, Model string
}

// Defaults returns o with its zero fields filled.
func (o Options) Defaults() Options {
	if o.Serial == "" {
		o.Serial = "00000001"
	}
	if o.Flag == "" {
		o.Flag = "SGM"
	}
	if o.Password == "" {
		o.Password = "ABCDEFGH"
	}
	if o.HLSSecret == "" {
		o.HLSSecret = "UTILITYSECRET016"
	}
	if o.FWSecret == "" {
		o.FWSecret = "FIRMWARESECRET16"
	}
	if o.SystemTitle == nil {
		st := []byte(o.Flag)
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], serialNumber(o.Serial))
		o.SystemTitle = append(st, n[3:]...)
	}
	if o.Rows == 0 {
		o.Rows = 4
	}
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	if o.Location == nil {
		o.Location = India()
	}
	if o.Firmware == "" {
		o.Firmware = "SIM-1.4.2"
	}
	if o.Category == "" {
		o.Category = "C1"
	}
	if o.Rating == "" {
		o.Rating = "10-60A"
	}
	if o.Model == "" {
		o.Model = "SIGMA SIM"
	}
	key := func(k *Keys, seed byte) {
		if k.Key == nil {
			k.Key = bytes.Repeat([]byte{seed}, 16)
		}
		if k.AuthKey == nil {
			k.AuthKey = bytes.Repeat([]byte{seed + 1}, 16)
		}
	}
	// One global key serves the reader, settings, firmware and push
	// associations (Part 2 clause 7.3.1 as amended).
	key(&o.HLSKeys, 0x30)
	if o.ReaderKeys.Key == nil {
		o.ReaderKeys = o.HLSKeys
	}
	if o.PushKeys.Key == nil {
		o.PushKeys = o.HLSKeys
	}
	key(&o.IHDKeys, 0x60)
	return o
}

// India is Asia/Kolkata, or a fixed +05:30 zone where the zone database
// is missing.
func India() *time.Location {
	if loc, err := time.LoadLocation("Asia/Kolkata"); err == nil {
		return loc
	}
	return time.FixedZone("IST", 5*3600+1800)
}

func serialNumber(s string) uint64 {
	var n uint64
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + uint64(c-'0')
		}
	}
	return n
}

// DeviceID is the meter's device ID: FLAG ID followed by the serial
// number (the push capture objects carry it).
func (o Options) DeviceID() string { return o.Flag + o.Serial }

// nameplateYear is the year of manufacture: the year before now.
func (o Options) nameplateYear() int {
	if o.Now.IsZero() {
		return time.Now().Year() - 1
	}
	return o.Now.Year() - 1
}

// Association is what the meter accepts from one client of the profile.
type Association struct {
	Role   is15959.Role
	Client uint16
	// Mechanism: 0 none, 1 low-level (Secret the password), 2 HLS with
	// Secret, 5 HLS-GMAC.
	Mechanism byte
	Secret    []byte
	// Policy protects APDUs (0x10 authenticated, 0x20 encrypted, 0x30
	// both) under Key and AuthKey.
	Policy       byte
	Key, AuthKey []byte
	// Setup is the association's security setup object; MasterKey the
	// KEK it holds.
	Setup     string
	MasterKey []byte
	// Unauthenticated: protected APDUs without authentication (the
	// in-home display).
	Unauthenticated bool
}

// PolicyOf is the security policy bits of a profile's security text.
func PolicyOf(s string) byte {
	switch s {
	case "authenticated":
		return 0x10
	case "encrypted":
		return 0x20
	case "authenticated-encrypted":
		return 0x30
	}
	return 0
}

// Associations are the profile's associations with o's secrets and keys;
// the push association gives the protection and keys of pushes.
func Associations(spec *is15959.Spec, o Options) []Association {
	o = o.Defaults()
	var out []Association
	for _, a := range spec.Associations {
		as := Association{Role: a.Role, Client: a.Client, Policy: PolicyOf(a.Security), Setup: a.Setup}
		switch {
		case a.Role == is15959.IHD:
			as.Unauthenticated, as.Key, as.AuthKey = true, o.IHDKeys.Key, o.IHDKeys.AuthKey
		case a.Role == is15959.Push:
			as.Key, as.AuthKey = o.PushKeys.Key, o.PushKeys.AuthKey
		case a.Auth == "low":
			as.Mechanism, as.Secret = 1, []byte(o.Password)
			as.Key, as.AuthKey = o.ReaderKeys.Key, o.ReaderKeys.AuthKey
		case strings.HasPrefix(a.Auth, "hls"):
			// Global keys are common to the reader, settings, firmware
			// and push associations (Part 2 clause 7.3.1, Amendment 1).
			as.Mechanism, as.Key, as.AuthKey = 5, o.HLSKeys.Key, o.HLSKeys.AuthKey
			as.MasterKey = bytes.Repeat([]byte{0x50}, 16)
			if a.Auth == "hls-aes" {
				as.Mechanism, as.Secret = 2, []byte(o.HLSSecret)
				if a.Role == is15959.FW {
					as.Secret = []byte(o.FWSecret)
				}
			}
		}
		out = append(out, as)
	}
	return out
}
