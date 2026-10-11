package hdlc

import "time"

// Scanner finds frames in a byte stream (6.4.1.2, 6.4.4.3.3): a frame runs
// from an opening flag over the octets its length field counts to a
// closing flag, which may also open the next frame (Figure 11). A gap
// longer than the inter-octet time-out ends a frame being received: what
// was gathered is dropped and the stream is scanned for the next opening
// flag.
type Scanner struct {
	// InterOctet is the inter-octet (inter-frame) time-out; 0 turns it off.
	InterOctet time.Duration
	buf        []byte
	last       time.Time
}

// maxBuffered bounds what the scanner keeps while looking for a frame.
const maxBuffered = 2 * (MaxFrameLength + 2)

// Feed adds octets received at now and returns the complete frames, each
// with both flags.
func (s *Scanner) Feed(p []byte, now time.Time) [][]byte {
	if s.InterOctet > 0 && len(s.buf) > 0 && !s.last.IsZero() && now.Sub(s.last) > s.InterOctet {
		s.buf = s.buf[:0]
	}
	s.last = now
	s.buf = append(s.buf, p...)
	var out [][]byte
	for {
		// Up to an opening flag.
		i := 0
		for i < len(s.buf) && s.buf[i] != Flag {
			i++
		}
		s.buf = s.buf[i:]
		if len(s.buf) < 3 {
			break
		}
		if s.buf[1]&0xF0 != formatType3 {
			// A flag that opens nothing (idle flags, or a closing flag
			// followed by a separate opening flag): move on.
			s.buf = s.buf[1:]
			continue
		}
		n := int(s.buf[1]&0x07)<<8 | int(s.buf[2])
		if n < 7 {
			s.buf = s.buf[1:]
			continue
		}
		if len(s.buf) < n+2 {
			break
		}
		if s.buf[n+1] != Flag {
			s.buf = s.buf[1:] // a false opening flag
			continue
		}
		out = append(out, append([]byte(nil), s.buf[:n+2]...))
		// Keep the closing flag: it may open the next frame.
		s.buf = s.buf[n+1:]
	}
	if len(s.buf) > maxBuffered {
		s.buf = s.buf[len(s.buf)-maxBuffered:]
	}
	return out
}

// Reset drops everything buffered: after a header check sequence error the
// frames concatenated to the bad one are discarded (6.4.4.9.2).
func (s *Scanner) Reset() { s.buf = s.buf[:0] }
