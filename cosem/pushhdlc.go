package cosem

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/cB-Sigma/dlms/hdlc"
	"github.com/cB-Sigma/dlms/phy"
)

// hdlcTrigger is the empty UI frame with P that gives a calling meter the
// right to talk.
func hdlcTrigger(size int) []byte {
	f := hdlc.Frame{
		Dest:    hdlc.ServerAddress(hdlc.ManagementDevice, hdlc.CallingFor(size), size),
		Src:     hdlc.ClientAddress(hdlc.ClientManagement),
		Control: hdlc.Control{Kind: hdlc.KindUI, PF: true}.Byte(),
	}
	b, _ := f.Encode()
	return b
}

// pushLLC removes the LLC header of a pushed MSDU.
func pushLLC(b []byte) ([]byte, bool) {
	if len(b) >= 3 && (b[0] == 0xE6 || b[0] == 0xFF) && (b[1] == 0xE7 || b[1] == 0xE6) && b[2] == 0x00 {
		return b[3:], true
	}
	return nil, false
}

// HDLCPushConfig is how ServeHDLCPushes takes a call.
type HDLCPushConfig struct {
	// Answer answers a Hayes modem's RING (ATA, then CONNECT; IEC 62056-42
	// A.2.3) before anything else; Identify runs the identification
	// service (6.3.3) and refuses another stack than COSEM; Trigger sends
	// the empty UI frame that gives the calling meter the right to talk,
	// with server addresses of AddressSize octets (1, 2 or 4).
	Answer, Identify, Trigger bool
	AddressSize               int
	// Inactivity closes a connection silent this long (default 10m).
	Inactivity time.Duration
	// Logger receives the refusals (nil: none).
	Logger *slog.Logger
}

// ServeHDLCPushes reads pushes in HDLC frames from a connection a meter
// (or a converter in front of it) opened, until it closes or stays silent
// for the inactivity time, and hands each APDU, its LLC header removed,
// to handle. UI frames are taken as they come (segmented ones joined); I
// frames are acknowledged with RR. It closes c, also when ctx ends.
func ServeHDLCPushes(ctx context.Context, c net.Conn, set HDLCPushConfig, handle func(from net.Addr, apdu []byte)) {
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	defer stop()
	log := set.Logger
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if set.Inactivity <= 0 {
		set.Inactivity = 10 * time.Minute
	}
	// The physical connection (IEC 62056-42): answer the modem, then the
	// optional identification service, before any HDLC frame.
	if set.Answer {
		rate, rest, err := phy.Answer(c, set.Inactivity)
		if err != nil {
			log.Warn("push: the call was not answered", "from", c.RemoteAddr().String(), "error", err)
			return
		}
		log.Info("push: call answered", "from", c.RemoteAddr().String(), "rate", rate)
		c = &phy.Prefixed{Conn: c, Prefix: rest}
	}
	if set.Identify {
		id, rest, err := phy.Identify(c, nil, 2*time.Second)
		c = &phy.Prefixed{Conn: c, Prefix: rest}
		if err == nil && id != phy.COSEM {
			err = fmt.Errorf("the meter's stack is %v", id)
		}
		if err != nil {
			log.Warn("push: identification failed; call dropped", "from", c.RemoteAddr().String(), "error", err)
			return
		}
	}
	if set.Trigger {
		_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := c.Write(hdlcTrigger(set.AddressSize)); err != nil {
			return
		}
	}
	var (
		sc   = hdlc.Scanner{InterOctet: time.Second}
		ui   []byte // UI segments so far
		iBuf []byte // I segments so far
		vr   int    // next N(S) we expect in an I frame
		tmp  = make([]byte, 4096)
	)
	deliver := func(msdu []byte) {
		apdu, ok := pushLLC(msdu)
		if !ok {
			log.Warn("push: HDLC information without the LLC header discarded", "from", c.RemoteAddr().String())
			return
		}
		handle(c.RemoteAddr(), apdu)
	}
	for {
		_ = c.SetReadDeadline(time.Now().Add(set.Inactivity))
		n, err := c.Read(tmp)
		for _, raw := range sc.Feed(tmp[:n], time.Now()) {
			f, derr := hdlc.Decode(raw)
			if errors.Is(derr, hdlc.ErrHCS) {
				sc.Reset()
				ui, iBuf = nil, nil
				break
			}
			if derr != nil || f.Dest.Size != 1 {
				log.Warn("push: HDLC frame refused", "from", c.RemoteAddr().String(), "error", derr)
				continue
			}
			ctl := hdlc.ParseControl(f.Control)
			switch ctl.Kind {
			case hdlc.KindUI:
				ui = append(ui, f.Info...)
				if f.Segmented {
					if len(ui) > maxGBT {
						ui = nil
					}
					continue
				}
				msdu := ui
				ui = nil
				if len(msdu) > 0 {
					deliver(msdu)
				}
			case hdlc.KindI:
				accepted := ctl.NS == vr
				if accepted {
					vr = (vr + 1) & 7
					iBuf = append(iBuf, f.Info...)
					if len(iBuf) > maxGBT {
						iBuf = nil
					}
				}
				rr := hdlc.Frame{Dest: f.Src, Src: f.Dest, Control: hdlc.Control{Kind: hdlc.KindRR, NR: vr, PF: true}.Byte()}
				if b, err := rr.Encode(); err == nil {
					if _, err := c.Write(b); err != nil {
						return
					}
				}
				if accepted && !f.Segmented && len(iBuf) > 0 {
					msdu := iBuf
					iBuf = nil
					deliver(msdu)
				}
			}
		}
		if err != nil {
			return
		}
	}
}
