package cosem

// Our own A-XDR encoding where gosem's is wrong. gosem v1.3.4 encodes
// null-data as 00 00 (the tag and a stray octet) instead of the single
// tag octet 00; push setup versions 1 and 2 need null-data in every push
// object definition (IEC 62056-6-2:2023 4.4.8.2.2.2, 5.4.10.2.2). We
// encode such a value ourselves and, since gosem's client offers no way to
// send pre-encoded data, a transport between gosem and the secure
// transport replaces gosem's bytes of that value with ours in the
// set-request, or in each set-request data block (IEC 62056-5-3:2023
// 7.3.3), before anything is protected or sent.

import (
	"bytes"
	"sync"
	"sync/atomic"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"
)

// EncodeAXDR returns the correct A-XDR encoding of d (r), gosem's encoding
// of it (g) and the positions in g of the octets gosem adds.
func EncodeAXDR(d *axdr.DlmsData) (r, g []byte, strays []int) {
	switch d.Tag {
	case axdr.TagNull:
		return []byte{0x00}, []byte{0x00, 0x00}, []int{1}
	case axdr.TagArray, axdr.TagStructure:
		items, _ := d.Value.([]*axdr.DlmsData)
		l, _ := axdr.EncodeLength(len(items))
		r = append([]byte{byte(d.Tag)}, l...)
		g = bytes.Clone(r)
		for _, it := range items {
			ri, gi, si := EncodeAXDR(it)
			for _, s := range si {
				strays = append(strays, len(g)+s)
			}
			r, g = append(r, ri...), append(g, gi...)
		}
		return r, g, strays
	}
	b, _ := d.Encode()
	return b, b, nil
}

// DropOctets returns b without the octets at the given (ascending) positions.
func DropOctets(b []byte, at []int) []byte {
	out := make([]byte, 0, len(b))
	j := 0
	for i, x := range b {
		if j < len(at) && at[j] == i {
			j++
			continue
		}
		out = append(out, x)
	}
	return out
}

// DecodeLength reads an A-XDR length.
func DecodeLength(b []byte) (n, size int) {
	switch {
	case len(b) == 0:
		return -1, 0
	case b[0] < 0x80:
		return int(b[0]), 1
	}
	k := int(b[0] & 0x7F)
	if k == 0 || k > 3 || len(b) < 1+k {
		return -1, 0
	}
	for _, x := range b[1 : 1+k] {
		n = n<<8 | int(x)
	}
	return n, 1 + k
}

// RawSetTransport sits between gosem's client and the secure transport.
// When armed with a value, it rewrites gosem's encoding of that value (g)
// into ours (r) in the set-request that carries it.
type RawSetTransport struct {
	gdlms.Transport
	mu     sync.Mutex
	g, r   []byte
	strays []int
	off    int // octets of g already sent in data blocks
	armed  bool
	// writes, when set, counts the set- and action-requests handed to
	// the transport, so a caller can tell a write that left from one that
	// did not.
	writes *atomic.Int64
	// alive, when set, says whether the link was still up when a request
	// was sent; one sent on a link already known closed never arrived.
	alive func() bool
}

// Arm makes the transport replace g, gosem's encoding of a value, with
// r, ours, in the next set-request (strays: the octets gosem adds).
func (t *RawSetTransport) Arm(g, r []byte, strays []int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.g, t.r, t.strays, t.off, t.armed = g, r, strays, 0, true
}

// Disarm stops the replacement.
func (t *RawSetTransport) Disarm() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.armed = false
}

// Send rewrites an armed value, then sends.
func (t *RawSetTransport) Send(src []byte) error {
	t.mu.Lock()
	if t.armed {
		src = t.rewrite(src)
	}
	t.mu.Unlock()
	up := t.alive == nil || t.alive()
	err := t.Transport.Send(src)
	if err == nil && up && t.writes != nil {
		apdu := src
		if len(src) >= 3 && (src[0] == 0xE6 || src[0] == 0xE7) && (src[1] == 0xE6 || src[1] == 0xE7) && src[2] == 0x00 {
			apdu = src[3:]
		}
		if len(apdu) > 0 && (apdu[0] == 0xC1 || apdu[0] == 0xC3) { // set-request, action-request
			t.writes.Add(1)
		}
	}
	return err
}

func (t *RawSetTransport) rewrite(src []byte) []byte {
	var llc []byte
	apdu := src
	if len(src) >= 3 && (src[0] == 0xE6 || src[0] == 0xE7) && (src[1] == 0xE6 || src[1] == 0xE7) && src[2] == 0x00 {
		llc, apdu = src[:3], src[3:]
	}
	if len(apdu) < 3 || apdu[0] != 0xC1 {
		return src
	}
	var head int
	switch apdu[1] {
	case 0x01: // set-request-normal: the value ends the APDU
		if !bytes.HasSuffix(apdu, t.g) {
			return src
		}
		out := append(bytes.Clone(llc), apdu[:len(apdu)-len(t.g)]...)
		return append(out, t.r...)
	case 0x02: // with-first-datablock: invoke, descriptor (9), no access selection
		head = 3 + 9 + 1
		t.off = 0
	case 0x03: // with-datablock
		head = 3
	default:
		return src
	}
	// DataBlock-SA: last-block, block-number (4), raw-data.
	if len(apdu) < head+6 {
		return src
	}
	l, sz := DecodeLength(apdu[head+5:])
	raw := apdu[head+5+sz:]
	if l != len(raw) || t.off+l > len(t.g) || !bytes.Equal(raw, t.g[t.off:t.off+l]) {
		return src
	}
	var at []int
	for _, s := range t.strays {
		if s >= t.off && s < t.off+l {
			at = append(at, s-t.off)
		}
	}
	t.off += l
	chunk := DropOctets(raw, at)
	nl, _ := axdr.EncodeLength(len(chunk))
	out := append(bytes.Clone(llc), apdu[:head+5]...)
	out = append(out, nl...)
	return append(out, chunk...)
}
