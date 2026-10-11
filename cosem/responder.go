// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package cosem

// The server (meter) side of general ciphering, general signing,
// third-party layers and V.44 compression (IEC 62056-5-3:2023 5.3.6, 5.5,
// 5.7, Table 26, annex J). Package server uses it; the client's code above
// it is the same, seen from the other end, so a client of this module and a
// server of this module share one implementation, and dlms-sim's meter,
// written separately, checks both.
//
// From the server's side the roles of Security turn round: SystemTitle,
// SignKey and KAKey are the server's own, MeterSignKey and MeterKAKey are
// the client's (the peer's). Responder hides that.

import (
	"crypto/ecdsa"
	"errors"
	"fmt"

	v44 "github.com/cB-Sigma/schc/v44"
)

// Responder holds a server's keys for one client.
type Responder struct {
	Suite       Suite
	SystemTitle []byte // the server's, 8 octets
	// Key and AuthKey are the global unicast and authentication keys,
	// BroadcastKey the global broadcast key, MasterKey the KEK that wraps
	// the content keys of wrapped-key general ciphering.
	Key, AuthKey, BroadcastKey, MasterKey []byte
	// SignKey and KAKey are the server's signing and key agreement keys;
	// ClientSignKey and ClientKAKey the client's public ones.
	SignKey       *ecdsa.PrivateKey
	KAKey         *ecdsa.PrivateKey
	ClientSignKey *ecdsa.PublicKey
	ClientKAKey   *ecdsa.PublicKey
	// Compression is the server's V.44 setting (nil: compressed requests
	// are refused); CompressAnswers compresses answers in general-glo,
	// general-ded and general ciphering when that makes them smaller.
	Compression     *CompressionParams
	CompressAnswers bool
	// ThirdParties are the third parties whose layers the server accepts
	// inside the client's protection.
	ThirdParties []ResponderThirdParty
}

// ResponderThirdParty is a third party as the server knows it.
type ResponderThirdParty struct {
	SystemTitle []byte
	// SignKey checks its general-signing layer and the ephemeral keys it
	// offers; KAKey is its static key agreement key; AuthKey the
	// authentication key of its general-ciphering layer.
	SignKey *ecdsa.PublicKey
	KAKey   *ecdsa.PublicKey
	AuthKey []byte
	// SignAnswers signs the answers for it when it signed the request
	// (annex J.2); otherwise a signed request gets an unsigned layer.
	SignAnswers bool
}

// Params checks a V.44 setting and returns it in the form Responder and
// Security use (Apply does the same and also checks it against a client's
// security settings).
func (c *Compression) Params() (*CompressionParams, error) {
	if c == nil || !c.Enabled {
		return nil, nil
	}
	p := v44.Params{Codewords: c.Codewords, MaxString: c.MaxStringLength, History: c.History}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("compression: %w", err)
	}
	full := v44.DefaultParams()
	if p.Codewords != 0 {
		full.Codewords = p.Codewords
	}
	if p.MaxString != 0 {
		full.MaxString = p.MaxString
	}
	full.History = p.History
	return &CompressionParams{params: full, requests: c.CompressRequests}, nil
}

// view is the Security the shared code expects, from the server's side.
func (r *Responder) view(generalKey byte) *Security {
	return &Security{Suite: r.Suite, SystemTitle: r.SystemTitle, Key: r.Key, AuthKey: r.AuthKey,
		MasterKey: r.MasterKey, BroadcastKey: r.BroadcastKey, GeneralKey: generalKey,
		SignKey: r.SignKey, KAKey: r.KAKey, MeterSignKey: r.ClientSignKey, MeterKAKey: r.ClientKAKey,
		Compression: r.Compression}
}

// Transaction is a request the server opened: what its answer must repeat.
type Transaction struct {
	header     generalHeader
	generalKey byte // the key-info kind the request used
	// Broadcast: the request was under the global broadcast key (never
	// answered).
	Broadcast bool
	// Compressed: the request was compressed.
	Compressed bool
}

// TransactionID is the request's transaction-id.
func (e *Transaction) TransactionID() []byte { return e.header.transactionID }

// OpenGloDed opens the ciphered content of a general-glo or general-ded
// request (or a service-specific one, where compression is refused) under
// key, from the holder of clientST; the broadcast key opens content whose
// key-set bit is set.
func (r *Responder) OpenGloDed(key, clientST, content []byte, compressionAllowed bool) (plain []byte, ic uint32, compressed bool, err error) {
	compressed = len(content) > 0 && content[0]&SecCompressed != 0
	if !compressionAllowed {
		plain, ic, err = UnprotectKeys(r.Suite, key, r.BroadcastKey, r.AuthKey, clientST, content, nil)
		return plain, ic, false, err
	}
	plain, ic, err = unprotectGeneral(r.Compression, r.Suite, key, r.BroadcastKey, r.AuthKey, clientST, content, nil)
	return plain, ic, compressed, err
}

// SealGloDed protects an answer for general-glo or general-ded ciphering:
// compressed first when CompressAnswers is set and it helps.
func (r *Responder) SealGloDed(policy byte, key []byte, ic uint32, resp []byte) ([]byte, error) {
	body, bit := r.compressAnswer(resp)
	return protectAAD(r.Suite, policy|bit, key, r.AuthKey, r.SystemTitle, ic, body, nil)
}

func (r *Responder) compressAnswer(resp []byte) ([]byte, byte) {
	if !r.CompressAnswers || r.Compression == nil || r.Suite == 0 {
		return resp, 0
	}
	out, err := v44.Compress(r.Compression.params, resp)
	if err != nil || len(out) >= len(resp) {
		return resp, 0
	}
	return out, SecCompressed
}

// OpenGeneral opens a general-ciphering request from the holder of
// clientST: the content key from its key-info (identified, wrapped,
// one-pass or static agreed), then the content, decompressed when the
// compression bit is set.
func (r *Responder) OpenGeneral(apdu, clientST []byte) (plain []byte, ic uint32, ex *Transaction, err error) {
	g, err := decodeGeneralCiphering(apdu)
	if err != nil {
		return nil, 0, nil, err
	}
	if string(g.originator) != string(clientST) {
		return nil, 0, nil, errors.New("the general-ciphering request names another originator")
	}
	ex = &Transaction{header: g.generalHeader}
	if len(g.recipient) == 0 && g.keyInfo != nil && g.keyInfo.choice == keyInfoIdentified && g.keyInfo.keyID == KeyGlobalBroadcast {
		ex.Broadcast = true
	} else if string(g.recipient) != string(r.SystemTitle) {
		return nil, 0, nil, errors.New("the general-ciphering request is for another recipient")
	}
	if g.keyInfo == nil {
		return nil, 0, nil, errors.New("the general-ciphering request has no key-info")
	}
	switch g.keyInfo.choice {
	case keyInfoIdentified:
		ex.generalKey = GenKeyIdentified
	case keyInfoWrapped:
		ex.generalKey = GenKeyWrapped
	case keyInfoAgreed:
		ex.generalKey = GenKeyOnePass
		if len(g.keyInfo.params) == 1 && g.keyInfo.params[0] == agreeStatic {
			ex.generalKey = GenKeyStatic
		}
	}
	if err := keySetZero(g.content); err != nil {
		return nil, 0, nil, err
	}
	key, err := r.view(ex.generalKey).recipientKey(g, nil)
	if err != nil {
		return nil, 0, nil, err
	}
	ex.Compressed = len(g.content) > 0 && g.content[0]&SecCompressed != 0
	plain, ic, err = unprotectGeneral(r.Compression, r.Suite, key, nil, r.AuthKey, g.originator, g.content, g.generalHeader.encode())
	if err != nil {
		return nil, 0, nil, err
	}
	return plain, ic, ex, nil
}

// SealGeneral answers a general-ciphering request: the same
// transaction-id, from the server to the client, under a fresh key of the
// kind the request used, with policy and the server's counter ic.
func (r *Responder) SealGeneral(ex *Transaction, policy byte, ic uint32, resp []byte) ([]byte, error) {
	h := generalHeader{transactionID: ex.header.transactionID, originator: r.SystemTitle, recipient: ex.header.originator, dateTime: cosemNow()}
	key, ki, err := r.view(ex.generalKey).originatorKey(h)
	if err != nil {
		return nil, err
	}
	body, bit := r.compressAnswer(resp)
	p, err := protectAAD(r.Suite, policy|bit, key, r.AuthKey, r.SystemTitle, ic, body, h.encode())
	if err != nil {
		return nil, err
	}
	return (&generalCiphering{generalHeader: h, keyInfo: ki, content: p}).encode(), nil
}

// OpenSigned checks a general-signing request from the holder of clientST
// with ClientSignKey and returns its content.
func (r *Responder) OpenSigned(apdu, clientST []byte) ([]byte, *Transaction, error) {
	g, err := decodeGeneralSigning(apdu)
	if err != nil {
		return nil, nil, err
	}
	if string(g.originator) != string(clientST) {
		return nil, nil, errors.New("the general-signing request names another originator")
	}
	if len(g.recipient) != 0 && string(g.recipient) != string(r.SystemTitle) {
		return nil, nil, errors.New("the general-signing request is for another recipient")
	}
	if r.ClientSignKey == nil || !verifyRaw(r.ClientSignKey, g.signed(), g.signature) {
		return nil, nil, errors.New("the client's signature does not verify")
	}
	if len(g.content) == 0 {
		return nil, nil, errors.New("the general-signing request is empty")
	}
	return g.content, &Transaction{header: g.generalHeader}, nil
}

// Sign wraps an answer in general-signing with SignKey, repeating the
// request's transaction-id.
func (r *Responder) Sign(ex *Transaction, resp []byte) ([]byte, error) {
	if r.SignKey == nil {
		return nil, errors.New("signing an answer needs the server's signing key")
	}
	g := &generalSigning{generalHeader: generalHeader{transactionID: ex.header.transactionID, originator: r.SystemTitle,
		recipient: ex.header.originator, dateTime: cosemNow()}, content: resp}
	var err error
	if g.signature, err = signRaw(r.SignKey, g.signed()); err != nil {
		return nil, err
	}
	return g.encode(), nil
}

// ThirdPartyTransaction records the layers a third party put on a request.
type ThirdPartyTransaction struct {
	tp       *ResponderThirdParty
	signTx   []byte
	signed   bool
	policy   byte // its general-ciphering layer's A and E bits; 0: none
	cipherEx *Transaction
}

// Signed says the third party signed the request; Policy is the
// protection of its ciphering layer (0: none).
func (t *ThirdPartyTransaction) Signed() bool { return t.signed }

// Policy is the A and E bits of the third party's general-ciphering layer.
func (t *ThirdPartyTransaction) Policy() byte { return t.policy }

// IsThirdParty says whether a deciphered request carries a layer from one
// of the server's third parties (general-ciphering or general-signing with
// one of their system titles as originator).
func (r *Responder) IsThirdParty(plain []byte) bool { return r.thirdPartyOf(plain) != nil }

func (r *Responder) thirdPartyOf(apdu []byte) *ResponderThirdParty {
	if len(apdu) == 0 {
		return nil
	}
	var orig []byte
	switch apdu[0] {
	case TagGeneralCiphering:
		g, err := decodeGeneralCiphering(apdu)
		if err != nil {
			return nil
		}
		orig = g.originator
	case TagGeneralSigning:
		g, err := decodeGeneralSigning(apdu)
		if err != nil {
			return nil
		}
		orig = g.originator
	default:
		return nil
	}
	for i := range r.ThirdParties {
		if string(r.ThirdParties[i].SystemTitle) == string(orig) {
			return &r.ThirdParties[i]
		}
	}
	return nil
}

// OpenThirdParty removes a third party's layers (general-ciphering with an
// agreed key outside, general-signing inside) from a request the client's
// own layer carried.
func (r *Responder) OpenThirdParty(apdu []byte) ([]byte, *ThirdPartyTransaction, error) {
	tp := r.thirdPartyOf(apdu)
	if tp == nil {
		return nil, nil, errors.New("the request carries no third party's layer the server knows")
	}
	out := &ThirdPartyTransaction{tp: tp}
	for len(apdu) > 0 && (apdu[0] == TagGeneralCiphering || apdu[0] == TagGeneralSigning) {
		switch apdu[0] {
		case TagGeneralCiphering:
			if out.policy != 0 || out.signed {
				return nil, nil, errors.New("the third party's layers are not general-signing inside general-ciphering")
			}
			g, err := decodeGeneralCiphering(apdu)
			if err != nil {
				return nil, nil, err
			}
			if string(g.originator) != string(tp.SystemTitle) || string(g.recipient) != string(r.SystemTitle) {
				return nil, nil, errors.New("the third party's general-ciphering layer is not from it to the server")
			}
			if g.keyInfo == nil || g.keyInfo.choice != keyInfoAgreed || len(g.keyInfo.params) != 1 || len(g.content) < 5 {
				return nil, nil, errors.New("a third party ciphers with an agreed key only")
			}
			gk := GenKeyOnePass
			if g.keyInfo.params[0] == agreeStatic {
				gk = GenKeyStatic
			}
			view := r.tpView(tp, gk)
			key, err := view.recipientKey(g, nil)
			if err != nil {
				return nil, nil, fmt.Errorf("the third party's layer: %w", err)
			}
			if err := keySetZero(g.content); err != nil {
				return nil, nil, err
			}
			plain, _, err := unprotectGeneral(r.Compression, r.Suite, key, nil, tp.AuthKey, g.originator, g.content, g.generalHeader.encode())
			if err != nil {
				return nil, nil, fmt.Errorf("the third party's layer: %w", err)
			}
			out.policy = g.content[0] & (SecAuthentication | SecEncryption)
			if out.policy == 0 {
				return nil, nil, errors.New("the third party's general-ciphering layer protects nothing")
			}
			out.cipherEx = &Transaction{header: g.generalHeader, generalKey: gk}
			apdu = plain
		case TagGeneralSigning:
			if out.signed {
				return nil, nil, errors.New("the request is signed twice by the third party")
			}
			g, err := decodeGeneralSigning(apdu)
			if err != nil {
				return nil, nil, err
			}
			if string(g.originator) != string(tp.SystemTitle) || (len(g.recipient) != 0 && string(g.recipient) != string(r.SystemTitle)) {
				return nil, nil, errors.New("the third party's general-signing layer is not from it to the server")
			}
			if tp.SignKey == nil || !verifyRaw(tp.SignKey, g.signed(), g.signature) {
				return nil, nil, errors.New("the third party's signature does not verify")
			}
			out.signed, out.signTx = true, g.transactionID
			apdu = g.content
		}
	}
	if len(apdu) == 0 {
		return nil, nil, errors.New("the third party's layers hold no request")
	}
	return apdu, out, nil
}

// tpView is the Security for the server's exchange with a third party.
func (r *Responder) tpView(tp *ResponderThirdParty, generalKey byte) *Security {
	return &Security{Suite: r.Suite, SystemTitle: r.SystemTitle, AuthKey: tp.AuthKey, GeneralKey: generalKey,
		SignKey: r.SignKey, KAKey: r.KAKey, MeterSignKey: tp.SignKey, MeterKAKey: tp.KAKey, Compression: r.Compression}
}

// AnswerThirdParty puts the server's layers for the third party around an
// answer: general-signing when it signed and SignAnswers is set, inside
// general-ciphering under a newly agreed key when it ciphered; with
// neither, general-ciphering with no protection (annex J.3).
func (r *Responder) AnswerThirdParty(t *ThirdPartyTransaction, resp []byte) ([]byte, error) {
	tp := t.tp
	tx := t.signTx
	if t.cipherEx != nil && tx == nil {
		tx = t.cipherEx.header.transactionID
	}
	sign := t.signed && tp.SignAnswers
	if !sign && t.policy == 0 {
		body, bit := r.compressAnswer(resp)
		h := generalHeader{transactionID: tx, originator: r.SystemTitle, recipient: tp.SystemTitle, dateTime: cosemNow()}
		return (&generalCiphering{generalHeader: h, content: concat([]byte{byte(r.Suite) | bit}, body)}).encode(), nil
	}
	out := resp
	if sign {
		if r.SignKey == nil {
			return nil, errors.New("signing for the third party needs the server's signing key")
		}
		g := &generalSigning{generalHeader: generalHeader{transactionID: tx, originator: r.SystemTitle, recipient: tp.SystemTitle, dateTime: cosemNow()}, content: out}
		var err error
		if g.signature, err = signRaw(r.SignKey, g.signed()); err != nil {
			return nil, err
		}
		out = g.encode()
	}
	if t.policy != 0 {
		h := generalHeader{transactionID: t.cipherEx.header.transactionID, originator: r.SystemTitle, recipient: tp.SystemTitle, dateTime: cosemNow()}
		key, ki, err := r.tpView(tp, t.cipherEx.generalKey).originatorKey(h)
		if err != nil {
			return nil, fmt.Errorf("the layer for the third party: %w", err)
		}
		body, bit := r.compressAnswer(out)
		// Every agreed key is new, so the counter under it is 0.
		p, err := protectAAD(r.Suite, t.policy|bit, key, tp.AuthKey, r.SystemTitle, 0, body, h.encode())
		if err != nil {
			return nil, err
		}
		out = (&generalCiphering{generalHeader: h, keyInfo: ki, content: p}).encode()
	}
	return out, nil
}
