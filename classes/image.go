// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package classes

import (
	"strings"
	"sync"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
)

// Image transfer status values (attribute 6 of class 18).
const (
	ImageNotInitiated          uint8 = 0
	ImageInitiated             uint8 = 1
	ImageVerificationInitiated uint8 = 2
	ImageVerificationOK        uint8 = 3
	ImageVerificationFailed    uint8 = 4
	ImageActivationInitiated   uint8 = 5
	ImageActivationOK          uint8 = 6
	ImageActivationFailed      uint8 = 7
)

// ImageTransfer is class 18: a firmware or other image sent in blocks,
// then verified and activated. The image is assembled in memory; OnVerify
// and OnActivate (when set) decide whether verification and activation
// succeed. Verification is done at once, so a verify answers with the
// final status rather than "in progress".
type ImageTransfer struct {
	sync.Mutex
	LN        string
	BlockSize uint32
	Enabled   bool
	Status    uint8
	// Signature is reported in to_activate_info with the image.
	Signature  []byte
	OnVerify   func(id, image []byte) error
	OnActivate func(id, image []byte) error

	id     []byte
	size   uint32
	image  []byte
	blocks []bool
}

func (o *ImageTransfer) ClassID() uint16     { return 18 }
func (o *ImageTransfer) Version() uint8      { return 0 }
func (o *ImageTransfer) LogicalName() string { return o.LN }

// Image returns the identifier and the bytes received so far.
func (o *ImageTransfer) Image() (id, image []byte) {
	o.Lock()
	defer o.Unlock()
	return append([]byte(nil), o.id...), append([]byte(nil), o.image...)
}

func (o *ImageTransfer) firstMissing() uint32 {
	for i, b := range o.blocks {
		if !b {
			return uint32(i)
		}
	}
	return uint32(len(o.blocks))
}

func (o *ImageTransfer) complete() bool {
	return o.Status != ImageNotInitiated && o.firstMissing() == uint32(len(o.blocks))
}

func (o *ImageTransfer) attrs() map[int8]attr {
	return map[int8]attr{
		2: readOnly(fU32(&o.BlockSize)),
		3: {get: func() (*axdr.DlmsData, error) {
			var sb strings.Builder
			for _, b := range o.blocks {
				if b {
					sb.WriteByte('1')
				} else {
					sb.WriteByte('0')
				}
			}
			return axdr.CreateAxdrBitString(sb.String()), nil
		}},
		4: {get: func() (*axdr.DlmsData, error) { return axdr.CreateAxdrDoubleLongUnsigned(o.firstMissing()), nil }},
		5: fBool(&o.Enabled),
		6: readOnly(fEnum(&o.Status)),
		7: {get: func() (*axdr.DlmsData, error) {
			if o.Status == ImageNotInitiated {
				return arrayOf(nil), nil
			}
			return arrayOf([]*axdr.DlmsData{structOf(axdr.CreateAxdrDoubleLongUnsigned(o.size),
				octetData(o.id), octetData(o.Signature))}), nil
		}},
	}
}

func (o *ImageTransfer) Get(a int8, sel *Selector) (*axdr.DlmsData, error) {
	o.Lock()
	defer o.Unlock()
	return getAttr(o.LN, o.attrs(), a, sel)
}

func (o *ImageTransfer) Set(a int8, v *axdr.DlmsData, sel *Selector) error {
	o.Lock()
	defer o.Unlock()
	return setAttr(o.attrs(), a, v, sel)
}

// Action runs image_transfer_initiate (1: {identifier, size}),
// image_block_transfer (2: {block number, block}), image_verify (3) and
// image_activate (4; a complete image not yet verified is verified
// first).
func (o *ImageTransfer) Action(m int8, p *axdr.DlmsData) (*axdr.DlmsData, error) {
	switch m {
	case 1:
		return nil, o.initiate(p)
	case 2:
		return nil, o.block(p)
	case 3:
		return nil, o.verify()
	case 4:
		return nil, o.activate()
	}
	return nil, ObjectUndefined
}

func (o *ImageTransfer) initiate(p *axdr.DlmsData) error {
	it, err := structItems(p, 2)
	if err != nil {
		return err
	}
	id, err := octetsOf(it[0])
	if err != nil {
		return err
	}
	size, err := u32Of(it[1])
	if err != nil {
		return err
	}
	o.Lock()
	defer o.Unlock()
	if !o.Enabled || o.BlockSize == 0 {
		return TemporaryFailure
	}
	if o.Status == ImageInitiated && o.blocks != nil && size == o.size && string(id) == string(o.id) {
		return nil // the same image again: the transfer resumes
	}
	n := (uint64(size) + uint64(o.BlockSize) - 1) / uint64(o.BlockSize)
	o.id, o.size = id, size
	o.image = make([]byte, size)
	o.blocks = make([]bool, n)
	o.Status = ImageInitiated
	return nil
}

func (o *ImageTransfer) block(p *axdr.DlmsData) error {
	it, err := structItems(p, 2)
	if err != nil {
		return err
	}
	bn, err := u32Of(it[0])
	if err != nil {
		return err
	}
	b, err := octetsOf(it[1])
	if err != nil {
		return err
	}
	o.Lock()
	defer o.Unlock()
	if !o.Enabled || o.Status != ImageInitiated {
		return TemporaryFailure
	}
	if uint64(bn) >= uint64(len(o.blocks)) {
		return BlockNumberInvalid
	}
	start := uint64(bn) * uint64(o.BlockSize)
	want := uint64(o.BlockSize)
	if rest := uint64(o.size) - start; rest < want {
		want = rest
	}
	if uint64(len(b)) != want {
		return OtherReason
	}
	copy(o.image[start:], b)
	o.blocks[bn] = true
	return nil
}

// runCheck sets status during, then ok or bad after f, called unlocked.
func (o *ImageTransfer) runCheck(during, good, bad uint8, f func(id, image []byte) error) error {
	o.Status = during
	id, img := append([]byte(nil), o.id...), append([]byte(nil), o.image...)
	o.Unlock()
	var err error
	if f != nil {
		err = f(id, img)
	}
	o.Lock()
	if err != nil {
		o.Status = bad
		return OtherReason
	}
	o.Status = good
	return nil
}

func (o *ImageTransfer) verify() error {
	o.Lock()
	defer o.Unlock()
	switch {
	case o.Status == ImageNotInitiated:
		return TemporaryFailure
	case !o.complete():
		o.Status = ImageVerificationFailed
		return OtherReason
	}
	return o.runCheck(ImageVerificationInitiated, ImageVerificationOK, ImageVerificationFailed, o.OnVerify)
}

func (o *ImageTransfer) activate() error {
	o.Lock()
	defer o.Unlock()
	if o.Status == ImageInitiated && o.complete() {
		if err := o.runCheck(ImageVerificationInitiated, ImageVerificationOK, ImageVerificationFailed, o.OnVerify); err != nil {
			return err
		}
	}
	if o.Status != ImageVerificationOK {
		return TemporaryFailure
	}
	return o.runCheck(ImageActivationInitiated, ImageActivationOK, ImageActivationFailed, o.OnActivate)
}
