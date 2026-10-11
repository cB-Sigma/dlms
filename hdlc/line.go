package hdlc

import (
	"io"
	"sync"
	"time"
)

// Line runs several secondary stations on one physical line (a multi-drop
// bus behind a converter, IEC 62056-7-6 9.6): each station sees every
// octet and keeps the frames addressed to it; their answers share the
// line. It also watches the master/slave rule: a primary that polls one
// station while another still has the right to talk (no frame with the
// final bit yet) is counted in Violations.
type Line struct {
	Stations []*Station

	mu         sync.Mutex
	talking    string // the station with the right to talk ("" none)
	violations int
}

// Violations is how many polls came while another station had the right
// to talk.
func (l *Line) Violations() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.violations
}

type lineWriter struct {
	l  *Line
	mu *sync.Mutex
	w  io.Writer
}

func (w lineWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if f, err := Decode(b); err == nil && ParseControl(f.Control).PF {
		w.l.mu.Lock()
		w.l.talking = ""
		w.l.mu.Unlock()
	}
	return w.w.Write(b)
}

// Serve runs the stations on rw until it ends.
func (l *Line) Serve(rw io.ReadWriter) error {
	var wmu sync.Mutex
	var pipes []*io.PipeWriter
	var wg sync.WaitGroup
	for _, st := range l.Stations {
		pr, pw := io.Pipe()
		pipes = append(pipes, pw)
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = st.Serve(struct {
				io.Reader
				io.Writer
			}{pr, lineWriter{l: l, mu: &wmu, w: rw}})
			_ = pr.Close()
		}()
	}
	var sc Scanner
	buf := make([]byte, 4096)
	var err error
	for {
		var n int
		n, err = rw.Read(buf)
		for _, raw := range sc.Feed(buf[:n], time.Now()) {
			l.watch(raw)
		}
		for _, pw := range pipes {
			if n > 0 {
				_, _ = pw.Write(buf[:n])
			}
		}
		if err != nil {
			break
		}
	}
	for _, pw := range pipes {
		_ = pw.Close()
	}
	wg.Wait()
	if err == io.EOF {
		return nil
	}
	return err
}

// watch notes which station a poll gives the right to talk.
func (l *Line) watch(raw []byte) {
	f, err := Decode(raw)
	if err != nil || f.Dest.Size == 1 && f.Src.Size != 1 {
		return
	}
	c := ParseControl(f.Control)
	if !c.PF || f.Dest.Broadcast() || f.Src.Size != 1 {
		return // not a poll from the primary to one station
	}
	to := f.Dest.String()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.talking != "" && l.talking != to {
		l.violations++
	}
	l.talking = to
}
