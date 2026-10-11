package iec6205621

// IEC 62056-21 annex C formatted codes: the four hex digit code in the
// address field of R2/R4 reads, W2/W4 writes and E2 executes, its data
// categories and fields, the data field of the season and load profile
// categories, and the annex's mnemonics.

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Category is a formatted code's data category (C.4).
type Category byte

// Data categories by the code's first hex digit.
const (
	CatRegister     Category = iota // 0xxx to 7xxx (the digit is the channel)
	CatSeason                       // 8xxx
	CatLoadProfile                  // 9xxx
	CatGroup                        // Axxx
	CatExtended                     // Bxxx, reserved for expansion
	CatVariable                     // Cxxx
	CatParameter                    // Dxxx
	CatReserved                     // Exxx
	CatManufacturer                 // Fxxx
)

// String names the category.
func (c Category) String() string {
	return [...]string{"register", "season", "load profile", "group", "extended function", "variable", "parameter", "reserved", "manufacturer-specific"}[c]
}

// Season access codes (C.4.2.1).
const (
	AccessSingle    = 0
	AccessSeasons   = 1
	AccessTariffs   = 2
	AccessRegisters = 3
	AccessTypes     = 4
	AccessChannels  = 5
)

// Load profile access codes (C.4.3.1).
const (
	LPRegister     = 0 // data and status records of the register only
	LPAll          = 1 // data and status records of all registers
	LPDataAll      = 2 // data records of all registers
	LPStatusAll    = 3 // status records of all registers
	GroupWildcards = 0 // the only defined group access type (C.4.4.1)
)

// Group wild card bits (Figure C.3), most significant first.
const (
	WildChannel  = 8
	WildType     = 4
	WildRegister = 2
	WildTariff   = 1
)

// Code is a decoded formatted code. Which fields apply depends on the
// category.
type Code struct {
	Raw      uint16
	Category Category
	Channel  int // register, season, load profile: 0 to 7
	Type     int // register, season: data type 0 to 3
	Register int // register, season, load profile: 0 to 63
	Tariff   int // register: 0 to 15
	Access   int // load profile access (0 to 3); group access type
	Wild     int // group: wild card bits
	Sub      int // variable or parameter type (the second hex digit)
	ID       int // variable or parameter identifier (the last two hex digits)
}

// ParseCode reads a four hex digit formatted code.
func ParseCode(s string) (Code, error) {
	if len(s) != 4 {
		return Code{}, fmt.Errorf("formatted code %q is not four hex digits", s)
	}
	v, err := strconv.ParseUint(s, 16, 16)
	if err != nil {
		return Code{}, fmt.Errorf("formatted code %q is not four hex digits", s)
	}
	x := int(v)
	c := Code{Raw: uint16(v)}
	switch top := x >> 12; {
	case top <= 7:
		c.Category, c.Channel = CatRegister, top
		c.Type, c.Register, c.Tariff = x>>10&3, x>>4&63, x&15
	case top == 8:
		// 1000 xccc ddrr rrrr: the register fields one digit to the right.
		c.Category, c.Channel, c.Type, c.Register = CatSeason, x>>8&7, x>>6&3, x&63
	case top == 9:
		// 1001 xccc llrr rrrr
		c.Category, c.Channel, c.Access, c.Register = CatLoadProfile, x>>8&7, x>>6&3, x&63
	case top == 0xA:
		// 1010 bbbb qqqq xxxx
		c.Category, c.Access, c.Wild = CatGroup, x>>8&15, x>>4&15
	case top == 0xB:
		c.Category = CatExtended
	case top == 0xC, top == 0xD:
		c.Category = CatVariable
		if top == 0xD {
			c.Category = CatParameter
		}
		c.Sub, c.ID = x>>8&15, x&255
	case top == 0xE:
		c.Category = CatReserved
	default:
		c.Category = CatManufacturer
	}
	return c, nil
}

// String is the code in four upper-case hex digits.
func (c Code) String() string { return fmt.Sprintf("%04X", c.Raw) }

// RegisterCode builds a register category code (C.4.1.1).
func RegisterCode(channel, typ, register, tariff int) string {
	return fmt.Sprintf("%04X", (channel&7)<<12|(typ&3)<<10|(register&63)<<4|tariff&15)
}

// SeasonCode builds a season category code and its data field (C.4.2.1).
func SeasonCode(channel, typ, register int) string {
	return fmt.Sprintf("%04X", 0x8000|(channel&7)<<8|(typ&3)<<6|register&63)
}

// SeasonData builds a season data field: tariff, season, access.
func SeasonData(tariff, season, access int) string {
	return fmt.Sprintf("%04X", (tariff&15)<<12|(season&255)<<4|access&15)
}

// ParseSeasonData reads a season data field.
func ParseSeasonData(s string) (tariff, season, access int, err error) {
	if len(s) != 4 {
		return 0, 0, 0, fmt.Errorf("season data %q is not four hex digits", s)
	}
	v, err := strconv.ParseUint(s, 16, 16)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("season data %q is not four hex digits", s)
	}
	return int(v >> 12), int(v >> 4 & 255), int(v & 15), nil
}

// LoadProfileCode builds a load profile code (C.4.3.1).
func LoadProfileCode(channel, access, register int) string {
	return fmt.Sprintf("%04X", 0x9000|(channel&7)<<8|(access&3)<<6|register&63)
}

// LoadProfileData is the data field of a load profile read or erase:
// YYMMDD of the first day and, when later, of the last (C.4.3.1).
func LoadProfileData(from, to time.Time) string {
	s := from.Format("060102")
	if t := to.Format("060102"); t > s {
		s += t
	}
	return s
}

// GroupCode builds a group code with wild card bits (C.4.4.1).
func GroupCode(wild int) string { return fmt.Sprintf("%04X", 0xA000|(wild&15)<<4) }

// ExecuteCode builds an E2 execute code (C.5.1): set and command.
func ExecuteCode(set, command int) string {
	return fmt.Sprintf("%04X", (set&15)<<8|command&255)
}

// Readable reports whether a code may be read with R2/R4, Writable
// whether W2/W4 may carry it (a write in the season, group and load
// profile categories erases). Extended and reserved codes are neither.
func (c Code) Readable() bool { return c.Category != CatExtended && c.Category != CatReserved }

// Writable reports whether a code may be written with W2/W4 (see Readable).
func (c Code) Writable() bool { return c.Readable() }

// Erases reports whether a W2 of this code erases records (C.3).
func (c Code) Erases() bool {
	return c.Category == CatSeason || c.Category == CatGroup || c.Category == CatLoadProfile
}

// ValidExecute reports whether s is an E2 code outside the reserved
// ranges: 0xxx execute or Fxxx manufacturer-specific (C.5).
func ValidExecute(s string) bool {
	c, err := ParseCode(s)
	return err == nil && (c.Raw>>12 == 0 || c.Raw>>12 == 0xF)
}

// singleAccess clears a season data field's access nibble.
func singleAccess(data string) string {
	if t, s, _, err := ParseSeasonData(data); err == nil {
		return SeasonData(t, s, AccessSingle)
	}
	return data
}

func typePart(t int) string {
	if t == 0 {
		return ""
	}
	return fmt.Sprintf("_t%d", t)
}

// Mnemonic is the annex's mnemonic for a code, with the season data field
// when the code is a season one: "c0_r2_t1" for 0021, "c0_t1_r1_t0" for
// 0410, "c0_r0_t1_m01" for 8000 with 1010, "c0_r0" for 9000. The data
// type appears only when it is not 0 (C.4.1.1). Categories without a
// mnemonic scheme give the code itself.
func Mnemonic(code, data string) string {
	c, err := ParseCode(code)
	if err != nil {
		return code
	}
	switch c.Category {
	case CatRegister:
		return fmt.Sprintf("c%d%s_r%d_t%d", c.Channel, typePart(c.Type), c.Register, c.Tariff)
	case CatSeason:
		t, s, a, err := ParseSeasonData(data)
		if err != nil {
			return fmt.Sprintf("c%d%s_r%d", c.Channel, typePart(c.Type), c.Register)
		}
		switch a {
		case AccessSingle:
			return fmt.Sprintf("c%d%s_r%d_t%d_m%02x", c.Channel, typePart(c.Type), c.Register, t, s)
		case AccessSeasons:
			return fmt.Sprintf("c%d%s_r%d_t%d_m*", c.Channel, typePart(c.Type), c.Register, t)
		case AccessTariffs:
			return fmt.Sprintf("c%d%s_r%d_t*", c.Channel, typePart(c.Type), c.Register)
		case AccessRegisters:
			return fmt.Sprintf("c%d_r*", c.Channel)
		case AccessTypes:
			return fmt.Sprintf("c%d_*", c.Channel)
		default:
			return "c*"
		}
	case CatLoadProfile:
		if c.Access != LPRegister {
			return fmt.Sprintf("c%d_r*", c.Channel)
		}
		return fmt.Sprintf("c%d_r%d", c.Channel, c.Register)
	}
	return c.String()
}

// Record is one data set of a formatted answer with its code resolved.
type Record struct {
	Code  string // four hex digits
	Data  string // the season data field, when the ID carried one
	Name  string // the mnemonic
	Value string
	Unit  string
	Time  string // a time stamp group "(YY-MM-DD hh:mm)", if any
	NoID  bool   // the data set had no ID
}

// Numeric reports whether the record's value is a quantity: register,
// season and load profile records are; variables, parameters and
// manufacturer-specific records keep their text.
func (r Record) Numeric() bool {
	c, err := ParseCode(r.Code)
	return err == nil && (c.Category == CatRegister || c.Category == CatSeason || c.Category == CatLoadProfile)
}

// Records resolves the IDs of a formatted answer. Register, variable
// and parameter records carry their code as the ID. Season records carry
// the code and the data field (eight digits); in a block of season
// records only the first may carry the code, and a four digit ID then is
// the data field of the same code (C.4.2.1, C.4.2.2).
func Records(ds []DataSet) ([]Record, error) { return RecordsOf(ds, "") }

// RecordsOf is Records where a data set without an ID takes the previous
// record's code, or def (the code read, e.g. a load profile's).
func RecordsOf(ds []DataSet, def string) ([]Record, error) {
	var out []Record
	season := ""
	for _, d := range ds {
		id := strings.TrimSpace(d.Address)
		r := Record{Value: d.Value, Unit: d.Unit}
		if len(d.Extra) > 0 {
			r.Time = d.Extra[0]
		}
		switch {
		case len(id) == 8:
			c, err := ParseCode(id[:4])
			if err != nil || c.Category != CatSeason {
				return out, fmt.Errorf("record ID %q is not a season code and data field", id)
			}
			if _, _, _, err := ParseSeasonData(id[4:]); err != nil {
				return out, err
			}
			season, r.Code, r.Data = id[:4], id[:4], id[4:]
		case len(id) == 4 && season != "":
			if _, _, _, err := ParseSeasonData(id); err != nil {
				return out, err
			}
			r.Code, r.Data = season, id
		case len(id) == 4:
			if _, err := ParseCode(id); err != nil {
				return out, err
			}
			r.Code = id
		case id == "":
			// A value without an ID continues the previous record's
			// sequence (6.6 note 1), e.g. load profile values.
			r.NoID, r.Code = true, def
			if len(out) > 0 && out[len(out)-1].Code != "" {
				r.Code, r.Data = out[len(out)-1].Code, out[len(out)-1].Data
			}
		default:
			return out, fmt.Errorf("record ID %q is not a formatted code", id)
		}
		// A returned season ID repeats the command's access nibble; the
		// record itself is one season location (C.4.2.2).
		r.Name = Mnemonic(r.Code, singleAccess(r.Data))
		if c, err := ParseCode(r.Code); err == nil && c.Category == CatLoadProfile {
			r.Name = "lp_" + r.Name
		}
		if r.Code == "" {
			r.Name = ""
		}
		out = append(out, r)
	}
	return out, nil
}
