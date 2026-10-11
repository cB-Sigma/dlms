package cosem

import (
	"encoding/binary"
	"errors"
	"fmt"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
)

// General block transfer for a request/answer link (DLMS over M-Bus): the
// xDLMS general-block-transfer APDU (tag E0h; gbt.go) carries an APDU
// that is too long for one exchange, whatever the service, after
// ciphering (the blocks carry the protected APDU). Every GBT we send and
// every one the meter sends is answered, so each round trip moves one
// block (window 1, no streaming):
//
//   - An APDU longer than Size goes as blocks 1..n of at most Size octets
//     each, the last with the last-block bit; the meter acknowledges each
//     non-last block with a GBT carrying block-number-ack and no data.
//   - The meter's answer may come the same way: we acknowledge each
//     non-last block with an empty GBT, and join the blocks.
//
// Both sides number their own GBT APDUs from 1, increasing with every
// GBT APDU sent even when its block data is empty; block-number-ack is the
// last block number received; once all our blocks are sent, our
// acknowledgements carry an empty block with the last-block bit set
// (IEC 62056-5-3:2023 7.3.13, 7.3.13.4). The window field is 1.

// BlockTransfer is one request's general block transfer on a
// request/answer link; a zero Size sends APDUs whole (answers in blocks
// are still joined).
type BlockTransfer struct {
	Size int

	out      [][]byte // our blocks
	sent     int      // our blocks sent
	num      uint16   // our last block number
	lastAck  uint16   // last block number received from the meter
	in       []byte   // the meter's blocks so far
	inStart  uint16   // the meter's first data block number
	inNext   uint16   // the meter's next data block number (0: none started)
	received int      // data blocks of the meter's last answer
}

// MaxGBT bounds an APDU joined from blocks.
const MaxGBT = maxGBT

// gbtAPDU encodes one general-block-transfer APDU.
func gbtAPDU(last bool, num, ack uint16, data []byte) []byte {
	ctrl := byte(0x01) // window 1, no streaming
	if last {
		ctrl |= 0x80
	}
	out := []byte{TagGBT, ctrl, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(out[2:], num)
	binary.BigEndian.PutUint16(out[4:], ack)
	l, _ := axdr.EncodeLength(len(data))
	return append(append(out, l...), data...)
}

// Send starts sending a (protected) APDU: whole, or its first block.
func (b *BlockTransfer) Send(apdu []byte) []byte {
	*b = BlockTransfer{Size: b.Size}
	if b.Size <= 0 || len(apdu) <= b.Size {
		return apdu
	}
	b.out = split(apdu, b.Size)
	return b.nextBlock()
}

func (b *BlockTransfer) nextBlock() []byte {
	d := b.out[b.sent]
	b.sent++
	b.num++
	return gbtAPDU(b.sent == len(b.out), b.num, b.lastAck, d)
}

// Blocks reports how many blocks we sent and how many of the meter's
// general-block-transfer APDUs carried data.
func (b *BlockTransfer) Blocks() (sent, received int) { return b.sent, b.received }

// Receive takes the meter's APDU: the next APDU to send (our next block or
// an acknowledgement), or the whole answer once it is complete.
func (b *BlockTransfer) Receive(w []byte) (next, answer []byte, err error) {
	if len(w) == 0 || w[0] != TagGBT {
		if b.sent < len(b.out) {
			return nil, nil, fmt.Errorf("the meter answered with APDU %02X before block %d of %d was sent", firstByte(w), b.sent+1, len(b.out))
		}
		if b.inNext > 0 {
			return nil, nil, errors.New("the meter's block transfer stopped before its last block")
		}
		return nil, w, nil
	}
	if len(w) < 7 {
		return nil, nil, errors.New("general-block-transfer APDU is too short")
	}
	ctrl := w[1]
	num := binary.BigEndian.Uint16(w[2:4])
	ack := binary.BigEndian.Uint16(w[4:6])
	data, rest, err := axdrOctets(w[6:])
	if err != nil || len(rest) != 0 {
		return nil, nil, fmt.Errorf("general-block-transfer block %d: the block data is malformed", num)
	}
	if ctrl&0x40 != 0 {
		return nil, nil, errors.New("the meter streams general block transfer blocks, which this link does not take (window 1)")
	}
	if b.sent < len(b.out) {
		// We are still sending: this must acknowledge our last block.
		if len(data) != 0 || ack != b.num {
			return nil, nil, fmt.Errorf("general-block-transfer acknowledgement of block %d, not %d", ack, b.num)
		}
		b.lastAck = num
		return b.nextBlock(), nil, nil
	}
	if len(data) == 0 && ctrl&0x80 == 0 {
		return nil, nil, errors.New("an empty general-block-transfer block from the meter that acknowledges nothing we sent")
	}
	if b.inNext == 0 {
		b.inStart, b.inNext = num, num
	}
	if num != b.inNext {
		return nil, nil, fmt.Errorf("general-block-transfer block %d arrived where %d was expected", num, b.inNext)
	}
	if len(b.in)+len(data) > maxGBT {
		return nil, nil, errors.New("general-block-transfer data is larger than 1 MiB")
	}
	b.in = append(b.in, data...)
	b.inNext++
	b.lastAck = num
	if ctrl&0x80 != 0 {
		out := b.in
		b.in, b.inNext = nil, 0
		b.received = int(num-b.inStart) + 1
		return nil, out, nil
	}
	b.num++
	return gbtAPDU(true, b.num, num, nil), nil, nil
}

func firstByte(b []byte) byte {
	if len(b) == 0 {
		return 0
	}
	return b[0]
}
