package phy

import (
	"errors"
	"net"
	"time"
)

// ServerIdentify is the server side physical layer's identification stage
// (6.3.3.3, Figure 6) on a connection just set up. It waits for the first
// octet, gathers octets until a gap longer than interOctet: up to three
// octets are an IDENTIFY.request, answered with id when it is one and
// addressed to us (device is our multidrop device ID, nil when we have
// none), then it waits again; a fourth octet ends identification for good,
// and the octets so far are returned to go to the data link layer
// (NOTE 3: a client not using identification starts with a longer frame).
// A malformed request is discarded without an answer.
func ServerIdentify(c net.Conn, id Identity, device *uint16, interOctet time.Duration) ([]byte, error) {
	return ServerIdentifyFunc(c, id, func(d *uint16) bool { return d == nil || (device != nil && *d == *device) }, interOctet)
}

// ServerIdentifyFunc is ServerIdentify for a line with several physical
// devices: own reports whether a request (with its device ID, or nil)
// is for a device on it.
func ServerIdentifyFunc(c net.Conn, id Identity, own func(*uint16) bool, interOctet time.Duration) ([]byte, error) {
	if interOctet <= 0 {
		interOctet = 25 * time.Millisecond
	}
	buf := make([]byte, 512)
	for {
		// Wait reception: the first octet, however long it takes.
		_ = c.SetReadDeadline(time.Time{})
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		got := append([]byte(nil), buf[:n]...)
		// Identification in progress: more octets until a gap.
		for len(got) <= 3 {
			_ = c.SetReadDeadline(time.Now().Add(interOctet))
			n, err := c.Read(buf)
			got = append(got, buf[:n]...)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					break // end of message
				}
				return nil, err
			}
		}
		_ = c.SetReadDeadline(time.Time{})
		if len(got) > 3 {
			return got, nil // data communications
		}
		want, err := ParseIdentifyRequest(got)
		if err != nil {
			continue // discarded, no answer
		}
		if !own(want) {
			continue // for another physical device
		}
		if _, err := c.Write(id.Bytes()); err != nil {
			return nil, err
		}
	}
}

// Prefixed is a connection whose first octets were already read.
type Prefixed struct {
	net.Conn
	Prefix []byte
}

// Read returns the prefix first, then reads the connection.
func (p *Prefixed) Read(b []byte) (int, error) {
	if len(p.Prefix) > 0 {
		n := copy(b, p.Prefix)
		p.Prefix = p.Prefix[n:]
		return n, nil
	}
	return p.Conn.Read(b)
}
