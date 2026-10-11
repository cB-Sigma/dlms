// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cosem

// Image transfer (IEC 62056-6-2 image transfer class 18) as a state
// machine on the client: check the object is enabled, read the block
// size, initiate (or resume an interrupted transfer of the same image),
// send the blocks, send again those the meter reports missing, verify and
// optionally activate, polling the transfer status while the meter
// works.

import (
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"
)

// Image transfer status values (attribute 6).
const (
	ImageNotInitiated          = 0
	ImageInitiated             = 1
	ImageVerificationInitiated = 2
	ImageVerificationOK        = 3
	ImageVerificationFailed    = 4
	ImageActivationInitiated   = 5
	ImageActivationOK          = 6
	ImageActivationFailed      = 7
)

// ImageTransfer is one image to send.
type ImageTransfer struct {
	// OBIS is the image transfer object (default 0.0.44.0.0.255).
	OBIS       string
	Identifier []byte
	Image      []byte
	// Activate runs image_activate after a successful verification.
	Activate bool
	// Poll is the interval of status reads while the meter verifies or
	// activates (default 1s); Wait bounds each wait (default 5 minutes).
	Poll, Wait time.Duration
	// Progress, when set, is told of each block sent.
	Progress func(sent, total uint32)
}

// ImageResult says what a transfer did.
type ImageResult struct {
	BlockSize uint32
	Blocks    uint32 // blocks in the image
	Sent      uint32 // blocks sent, resends included
	Resumed   bool   // the meter already held part of this image
	Status    uint8  // the last transfer status read
}

// TransferImage sends an image to the meter on the open association.
func (c *Client) TransferImage(it ImageTransfer) (ImageResult, error) {
	var res ImageResult
	if c.a == nil {
		return res, errNoAssociation
	}
	if it.OBIS == "" {
		it.OBIS = "0.0.44.0.0.255"
	}
	if it.Poll <= 0 {
		it.Poll = time.Second
	}
	if it.Wait <= 0 {
		it.Wait = 5 * time.Minute
	}
	if len(it.Image) == 0 || len(it.Identifier) == 0 {
		return res, errors.New("an image transfer needs an identifier and an image")
	}
	num := func(attr int8) (uint32, error) {
		v, err := c.Get(18, it.OBIS, attr)
		if err != nil {
			return 0, fmt.Errorf("image transfer attribute %d: %w", attr, err)
		}
		n, ok := Number(v)
		if !ok {
			return 0, fmt.Errorf("image transfer attribute %d is not a number", attr)
		}
		return uint32(n), nil
	}
	if v, err := c.Get(18, it.OBIS, 5); err != nil {
		return res, fmt.Errorf("image transfer enabled: %w", err)
	} else if on, _ := v.Value.(bool); !on {
		return res, errors.New("image transfer is not enabled in the meter")
	}
	bs, err := num(2)
	if err != nil {
		return res, err
	}
	if bs == 0 {
		return res, errors.New("the meter's image block size is 0")
	}
	res.BlockSize = bs
	res.Blocks = uint32((len(it.Image) + int(bs) - 1) / int(bs))
	act := func(m int8, p *axdr.DlmsData) error {
		return c.a.Client.ActionRequest(gdlms.CreateMethodDescriptor(18, it.OBIS, m), p)
	}
	octets := func(b []byte) *axdr.DlmsData { return axdr.CreateAxdrOctetString(hex.EncodeToString(b)) }
	// image_transfer_initiate; a meter holding part of the same image keeps it.
	if err := act(1, axdr.CreateAxdrStructure([]*axdr.DlmsData{octets(it.Identifier), axdr.CreateAxdrDoubleLongUnsigned(uint32(len(it.Image)))})); err != nil {
		return res, fmt.Errorf("image_transfer_initiate: %w", err)
	}
	first, err := num(4)
	if err != nil {
		return res, err
	}
	res.Resumed = first > 0
	for round := 0; first < res.Blocks; round++ {
		if round == 3 {
			return res, fmt.Errorf("the meter still misses block %d after three rounds", first)
		}
		for bn := first; bn < res.Blocks; bn++ {
			end := min(int(bn+1)*int(bs), len(it.Image))
			b := it.Image[int(bn)*int(bs) : end]
			if err := act(2, axdr.CreateAxdrStructure([]*axdr.DlmsData{axdr.CreateAxdrDoubleLongUnsigned(bn), octets(b)})); err != nil {
				return res, fmt.Errorf("image_block_transfer %d: %w", bn, err)
			}
			res.Sent++
			if it.Progress != nil {
				it.Progress(bn+1, res.Blocks)
			}
		}
		if first, err = num(4); err != nil {
			return res, err
		}
	}
	wait := func(during, good, bad uint8) error {
		deadline := time.Now().Add(it.Wait)
		for {
			st, err := num(6)
			if err != nil {
				return err
			}
			res.Status = uint8(st)
			switch uint8(st) {
			case good:
				return nil
			case bad:
				return fmt.Errorf("the meter reports image transfer status %d", st)
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("image transfer status still %d after %v", st, it.Wait)
			}
			time.Sleep(it.Poll)
		}
	}
	// image_verify: a meter that verifies in the background answers
	// temporary-failure and reports the outcome in the status.
	if err := act(3, axdr.CreateAxdrInteger(0)); err != nil && !Rejected(err) {
		return res, fmt.Errorf("image_verify: %w", err)
	}
	if err := wait(ImageVerificationInitiated, ImageVerificationOK, ImageVerificationFailed); err != nil {
		return res, fmt.Errorf("image verification: %w", err)
	}
	if !it.Activate {
		return res, nil
	}
	if err := act(4, axdr.CreateAxdrInteger(0)); err != nil && !Rejected(err) {
		return res, fmt.Errorf("image_activate: %w", err)
	}
	if err := wait(ImageActivationInitiated, ImageActivationOK, ImageActivationFailed); err != nil {
		return res, fmt.Errorf("image activation: %w", err)
	}
	return res, nil
}
