package cosem

// General block transfer (DLMS UA Green Book, xDLMS general-block-transfer
// APDU, tag 0xE0): block-control (bit 7 last block, bit 6 streaming, bits
// 0 to 5 window), block-number and block-number-ack (unsigned 16 each),
// then block-data as an octet string. IS 15959 Part 2 table 2 lists it
// for the push association: a long push arrives as numbered blocks, which
// are joined here into the APDU they carry.

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// TagGBT is the general-block-transfer APDU tag.
const TagGBT byte = 0xE0

// maxGBT bounds a reassembled APDU.
const maxGBT = 1 << 20

// GBTAssembler joins one sender's blocks.
type GBTAssembler struct {
	next uint16 // block number expected (0: none started)
	buf  []byte
}

// Add takes one block and returns the whole APDU after the last block,
// or nil while more are expected. Blocks must come in order from 1.
func (g *GBTAssembler) Add(apdu []byte) ([]byte, error) {
	if len(apdu) < 6 || apdu[0] != TagGBT {
		return nil, errors.New("not a general-block-transfer APDU")
	}
	ctrl := apdu[1]
	n := binary.BigEndian.Uint16(apdu[2:4])
	data, rest, err := axdrOctets(apdu[6:])
	if err != nil || len(rest) != 0 {
		g.reset()
		return nil, fmt.Errorf("general-block-transfer block %d: the block data is malformed", n)
	}
	if n == 1 {
		g.reset()
		g.next = 1
	}
	if g.next == 0 || n != g.next {
		want := g.next
		g.reset()
		return nil, fmt.Errorf("general-block-transfer block %d arrived where %d was expected", n, want)
	}
	if len(g.buf)+len(data) > maxGBT {
		g.reset()
		return nil, errors.New("general-block-transfer data is larger than 1 MiB")
	}
	g.buf = append(g.buf, data...)
	g.next++
	if ctrl&0x80 == 0 {
		return nil, nil
	}
	out := g.buf
	g.reset()
	return out, nil
}

func (g *GBTAssembler) reset() { g.next, g.buf = 0, nil }

// axdrOctets reads an A-XDR octet string (length, then bytes).
func axdrOctets(b []byte) (data, rest []byte, err error) {
	if len(b) == 0 {
		return nil, nil, errors.New("missing length")
	}
	n, size := int(b[0]), 1
	if b[0]&0x80 != 0 {
		k := int(b[0] & 0x7F)
		if k == 0 || k > 3 || len(b) < 1+k {
			return nil, nil, errors.New("bad length")
		}
		n = 0
		for _, x := range b[1 : 1+k] {
			n = n<<8 | int(x)
		}
		size = 1 + k
	}
	if len(b) < size+n {
		return nil, nil, errors.New("the data is cut short")
	}
	return b[size : size+n], b[size+n:], nil
}
