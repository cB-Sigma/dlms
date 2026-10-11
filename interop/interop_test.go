// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"
	gdlms "gitlab.com/circutor-library/gosem/pkg/dlms"

	"github.com/cB-Sigma/dlms/cosem"
	"github.com/cB-Sigma/dlms/hdlc"
	"github.com/cB-Sigma/dlms/phy"
	"github.com/cB-Sigma/dlms/wrapper"
)

// The peer: Gurux.DLMS.Java's server example at this commit, built in this
// image. Its pom takes gurux.dlms 4.0.95 from Maven Central.
const (
	image       = "maven:3.9.9-eclipse-temurin-17"
	guruxCommit = "709c3a0922c91bf5549aa08bd545dd7e4362d25b"
)

// What the Gurux example serves (GXDLMSBase.java): logical name
// referencing over HDLC on port 4061 and over the wrapper on 4063; server
// address 1; one association object per client address: 16 public (get
// only, three objects), 17 low-level security with password "Gurux", 18
// HLS mechanism 2 with secret "Gurux", 21 HLS-GMAC (mechanism 5), 24 HLS
// mechanism 2 with ciphering. The register 1.1.21.25.0.255, the clock and
// a profile 1.0.99.1.0.255 of 10 000 hourly rows (clock, register).
const (
	ldn      = "0.0.42.0.0.255"
	icPublic = "0.0.43.1.0.255"
	fwVer    = "1.0.0.2.0.255"
	clockLN  = "0.0.1.0.0.255"
	register = "1.1.21.25.0.255"
	profile  = "1.0.99.1.0.255"
)

type server struct {
	name           string
	owned          bool
	wrapper, hdlcA string
	st, ak, bk     []byte
}

var (
	peerOnce sync.Once
	peer     *server
	peerErr  error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if peer != nil && peer.owned {
		_ = exec.Command("docker", "container", "rm", "-f", peer.name).Run()
	}
	os.Exit(code)
}

// needPeer starts the Gurux server once (or uses the running container
// named by SIGMA_DLMS_GURUX_CONTAINER) and returns its addresses and keys.
func needPeer(t *testing.T) *server {
	t.Helper()
	if os.Getenv("SIGMA_DLMS_INTEROP") != "1" {
		t.Skip("starts the Gurux DLMS server in Docker; set SIGMA_DLMS_INTEROP=1 to run")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not on PATH")
	}
	peerOnce.Do(func() { peer, peerErr = startPeer() })
	if peerErr != nil {
		t.Fatal(peerErr)
	}
	return peer
}

func startPeer() (*server, error) {
	s := &server{name: os.Getenv("SIGMA_DLMS_GURUX_CONTAINER")}
	if s.name == "" {
		td, err := filepath.Abs("testdata")
		if err != nil {
			return nil, err
		}
		s.name = fmt.Sprintf("sigma-dlms-gurux-%d", os.Getpid())
		out, err := exec.Command("docker", "run", "-d", "-i", "--name", s.name,
			"-p", "127.0.0.1::4061", "-p", "127.0.0.1::4063",
			"-v", td+":/sigma:ro", image, "sh", "/sigma/gurux-server.sh", guruxCommit).CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("docker run: %v: %s", err, out)
		}
		s.owned = true
		peer = s // removed by TestMain even when it never comes up
	}
	var logs string
	deadline := time.Now().Add(10 * time.Minute)
	for {
		out, err := exec.Command("docker", "logs", s.name).CombinedOutput()
		logs = string(out)
		if err == nil && strings.Contains(logs, "Press Enter to close.") {
			break
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("the Gurux server did not start: %s", logs)
		}
		time.Sleep(2 * time.Second)
	}
	key := func(prefix string) []byte {
		for _, l := range strings.Split(logs, "\n") {
			if strings.HasPrefix(l, prefix) {
				b, _ := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(strings.TrimPrefix(l, prefix)), " ", ""))
				return b
			}
		}
		return nil
	}
	s.st, s.ak, s.bk = key("System Title: "), key("Authentication key: "), key("Block cipher key: ")
	port := func(p string) (string, error) {
		out, err := exec.Command("docker", "port", s.name, p+"/tcp").Output()
		if err != nil {
			return "", fmt.Errorf("docker port %s: %v", p, err)
		}
		return strings.TrimSpace(strings.Split(string(out), "\n")[0]), nil
	}
	var err error
	if s.wrapper, err = port("4063"); err != nil {
		return nil, err
	}
	if s.hdlcA, err = port("4061"); err != nil {
		return nil, err
	}
	return s, nil
}

type link int

const (
	overWrapper link = iota
	overHDLC
)

func (l link) String() string { return [...]string{"wrapper", "HDLC"}[l] }

// connect opens an association of client with the given security.
func connect(t *testing.T, s *server, l link, client int, sec cosem.SecurityConfig, password string) *cosem.Client {
	t.Helper()
	sec.Name = "gurux"
	h, _, err := sec.Build()
	if err != nil {
		t.Fatal(err)
	}
	tr := func(c int) (gdlms.Transport, error) {
		if l == overWrapper {
			w, err := wrapper.New("tcp", s.wrapper, c, 1, 10*time.Second)
			if err != nil {
				return nil, err
			}
			return counting{w}, nil
		}
		line, err := phy.NewPort(phy.Config{Open: func() (net.Conn, error) { return net.DialTimeout("tcp", s.hdlcA, 5*time.Second) }})
		if err != nil {
			return nil, err
		}
		h, err := hdlc.NewClient(line, hdlc.Config{Client: c, Server: hdlc.ServerAddress(1, 0, 1)})
		if err != nil {
			return nil, err
		}
		return counting{h}, nil
	}
	cfg := cosem.ClientConfig{Transport: tr, ClientAddress: client, HLS: h, Password: []byte(password),
		Timeout: 20 * time.Second, Name: "gurux", Where: l.String()}
	if h.Security.Policy != 0 {
		// The ciphered associations share security setup 0.0.43.0.8.255,
		// whose invocation counter (0.0.43.1.8.255, readable by the
		// public client) the server checks.
		cfg.InvocationCounter = &cosem.FrameCounterObject{OBIS: "0.0.43.1.8.255"}
	}
	c := cosem.NewClient(cfg)
	if err := c.Connect(); err != nil {
		t.Fatalf("association of client %d over the %s: %v", client, l, err)
	}
	t.Cleanup(c.Close)
	return c
}

// sent counts the APDUs the client sent (tests run one at a time), so a
// read can tell how many requests it took: a GET answered in blocks takes
// one more request per block.
var sent atomic.Int64

type counting struct{ gdlms.Transport }

func (c counting) Send(b []byte) error {
	sent.Add(1)
	return c.Transport.Send(b)
}

func get(t *testing.T, c *cosem.Client, class uint16, obis string, attr int8) axdr.DlmsData {
	t.Helper()
	v, err := c.Get(class, obis, attr)
	if err != nil {
		t.Fatalf("get %d/%s/%d: %v", class, obis, attr, err)
	}
	return v
}

// readClock reads the clock's time and checks it is a valid date-time
// within a day of ours (the container's clock is the host's).
func readClock(t *testing.T, c *cosem.Client) {
	t.Helper()
	v := get(t, c, 8, clockLN, 2)
	var tm time.Time
	switch x := v.Value.(type) {
	case time.Time:
		tm = x
	case string:
		var ok bool
		if tm, ok = cosem.DateTime(x, time.UTC); !ok {
			t.Fatalf("clock time %q is not a COSEM date-time", x)
		}
	default:
		t.Fatalf("clock time is %T (%v)", v.Value, v.Value)
	}
	if d := time.Since(tm); d > 24*time.Hour || d < -24*time.Hour {
		t.Errorf("clock time %v is far from now", tm)
	}
	t.Logf("clock: %v", tm)
}

func readRegister(t *testing.T, c *cosem.Client) {
	t.Helper()
	v := get(t, c, 3, register, 2)
	n, ok := cosem.Number(v)
	if !ok {
		t.Fatalf("register value is not a number: %#v", v)
	}
	su := get(t, c, 3, register, 3)
	sc, unit, err := cosem.ScalerUnit(su)
	if err != nil {
		t.Fatalf("scaler_unit: %v", err)
	}
	t.Logf("register: %v scaler %d unit %d (%s)", n, sc, unit, cosem.UnitSymbol(unit))
}

func readText(t *testing.T, c *cosem.Client, obis string) string {
	t.Helper()
	v := get(t, c, 1, obis, 2)
	switch x := cosem.Readable(v, time.UTC, false).(type) {
	case string:
		return x
	default:
		t.Fatalf("%s value is %T (%v)", obis, x, x)
	}
	return ""
}

// Public client (16), no security: the logical device name and the
// invocation counter, the only objects its association lists.
func TestNoSecurity(t *testing.T) {
	s := needPeer(t)
	for _, l := range []link{overWrapper, overHDLC} {
		t.Run(l.String(), func(t *testing.T) {
			c := connect(t, s, l, 16, cosem.SecurityConfig{Authentication: "none"}, "")
			if got := readText(t, c, ldn); !strings.HasPrefix(got, "GRX") {
				t.Errorf("logical device name %q", got)
			}
			ic, ok := cosem.Number(get(t, c, 1, icPublic, 2))
			if !ok {
				t.Error("invocation counter is not a number")
			}
			t.Logf("invocation counter %v", ic)
		})
	}
}

// Low-level security (client 17, password "Gurux"): clock, register with
// scaler and unit, a data object.
func TestLowLevelSecurity(t *testing.T) {
	s := needPeer(t)
	for _, l := range []link{overWrapper, overHDLC} {
		t.Run(l.String(), func(t *testing.T) {
			c := connect(t, s, l, 17, cosem.SecurityConfig{Authentication: "low", Password: "Gurux"}, "Gurux")
			readClock(t, c)
			readRegister(t, c)
			t.Logf("firmware version %q", readText(t, c, fwVer))
		})
	}
}

// A wrong low-level password is refused by the peer and reported as such.
func TestLowLevelSecurityWrongPassword(t *testing.T) {
	s := needPeer(t)
	h, _, _ := (&cosem.SecurityConfig{Authentication: "low", Password: "wrong"}).Build()
	c := cosem.NewClient(cosem.ClientConfig{Transport: func(c int) (gdlms.Transport, error) {
		return wrapper.New("tcp", s.wrapper, c, 1, 10*time.Second)
	}, ClientAddress: 17, HLS: h, Password: []byte("wrong"), Timeout: 10 * time.Second, Name: "gurux"})
	err := c.Connect()
	if err == nil {
		c.Close()
		t.Fatal("association with a wrong password accepted")
	}
	t.Logf("refused as expected: %v", err)
}

// guruxHLSKey is the example's mechanism 2 secret "Gurux" as the AES-128
// key Gurux makes of it (zero-padded to 16 octets). Mechanism 2 is
// manufacturer-specific; we, like IS 15959, take the secret as the key
// itself and refuse one that is not an AES key length.
const guruxHLSKey = "Gurux\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

// HLS mechanism 2 (client 18), no APDU protection.
func TestHLSMechanism2(t *testing.T) {
	s := needPeer(t)
	c := connect(t, s, overWrapper, 18, cosem.SecurityConfig{Authentication: "hls-aes", Password: guruxHLSKey}, "")
	readClock(t, c)
}

// HLS mechanism 2 with authenticated and encrypted APDUs (client 24, the
// example's ciphered association; security setup 0.0.43.0.8.255 holds
// the same global keys as the server's ciphering).
func TestHLSMechanism2Ciphered(t *testing.T) {
	s := needPeer(t)
	c := connect(t, s, overWrapper, 24, cosem.SecurityConfig{Authentication: "hls-aes", Password: guruxHLSKey,
		Security: "authenticated-encrypted", BlockCipherKey: hex.EncodeToString(s.bk), AuthenticationKey: hex.EncodeToString(s.ak)}, "")
	readClock(t, c)
	readRegister(t, c)
}

// HLS-GMAC (mechanism 5, client 21), security suite 0, authenticated and
// encrypted APDUs under the server's global keys (the wrapper port, whose
// client 21 testdata/gurux-server.sh gives the ciphering context).
func TestHLSGMAC(t *testing.T) {
	s := needPeer(t)
	c := connect(t, s, overWrapper, 21, cosem.SecurityConfig{Authentication: "hls-gmac", Security: "authenticated-encrypted",
		BlockCipherKey: hex.EncodeToString(s.bk), AuthenticationKey: hex.EncodeToString(s.ak)}, "")
	if st := c.MeterSystemTitle(); !equal(st, s.st) {
		t.Errorf("meter system title %X, the server printed %X", st, s.st)
	}
	readClock(t, c)
	readRegister(t, c)
	readProfile(t, c, true)
}

// HLS-GMAC with Gurux's default settings (the HDLC port, unchanged):
// client 21 takes only logical name referencing without ciphering and
// plain APDUs. The client's automatic context (ciphering, since our system
// title is sent) is refused with diagnostic 2; applicationContext "ln"
// associates and reads.
func TestHLSGMACDefaultContext(t *testing.T) {
	s := needPeer(t)
	sec := cosem.SecurityConfig{Name: "gurux", Authentication: "hls-gmac", Security: "none",
		BlockCipherKey: hex.EncodeToString(s.bk), AuthenticationKey: hex.EncodeToString(s.ak)}
	h, _, err := sec.Build()
	if err != nil {
		t.Fatal(err)
	}
	c := cosem.NewClient(cosem.ClientConfig{Transport: func(c int) (gdlms.Transport, error) {
		line, err := phy.NewPort(phy.Config{Open: func() (net.Conn, error) { return net.DialTimeout("tcp", s.hdlcA, 5*time.Second) }})
		if err != nil {
			return nil, err
		}
		return hdlc.NewClient(line, hdlc.Config{Client: c, Server: hdlc.ServerAddress(1, 0, 1)})
	}, ClientAddress: 21, HLS: h, Timeout: 20 * time.Second, Name: "gurux", Where: "HDLC"})
	if err := c.Connect(); err == nil {
		c.Close()
		t.Error("the ciphering context was accepted by Gurux's default GMAC association")
	} else {
		t.Logf("automatic context refused as expected: %v", err)
	}

	sec.ApplicationContext = "ln"
	cl := connect(t, s, overHDLC, 21, sec, "")
	if st := cl.MeterSystemTitle(); !equal(st, s.st) {
		t.Errorf("meter system title %X, the server printed %X", st, s.st)
	}
	readClock(t, cl)
	readRegister(t, cl)
	readProfile(t, cl, false)
}

func equal(a, b []byte) bool { return hex.EncodeToString(a) == hex.EncodeToString(b) }

// readProfile reads the profile's columns, then its buffer: whole (10 000
// rows, far more than one 1024-octet PDU, so with block transfer) when
// whole is set, and by range.
func readProfile(t *testing.T, c *cosem.Client, whole bool) {
	t.Helper()
	cl := c.Association().Client
	cols, err := cosem.ReadCaptureObjects(cl, profile)
	if err != nil {
		t.Fatalf("capture objects: %v", err)
	}
	if len(cols) != 2 || cols[0].OBIS != clockLN || cols[1].OBIS != register {
		t.Fatalf("capture objects %+v", cols)
	}
	tc, ok := cosem.TimeColumn(cols)
	if !ok {
		t.Fatal("no time column")
	}
	if whole {
		before := sent.Load()
		v := get(t, c, 7, profile, 2)
		requests := sent.Load() - before
		rows, _ := v.Value.([]*axdr.DlmsData)
		if len(rows) < 1000 {
			t.Errorf("buffer has %d rows", len(rows))
		}
		if requests < 2 {
			t.Errorf("the whole buffer took %d request: not block transfer", requests)
		}
		t.Logf("whole buffer: %d rows in %d blocks (requests)", len(rows), requests)
		if len(rows) > 0 {
			_, tm := cosem.ProfileRow(rows[len(rows)-1], cols, cosem.RowScalers{Location: time.UTC})
			t.Logf("last row at %v", tm)
		}
	}
	// The example's by-range handler takes the range's start for its end
	// too (getProfileGenericDataByRange reads element 1 twice), so it
	// answers the one row stamped exactly at the start: a start on a
	// whole hour, where its hourly rows are, must come back as that row.
	from := time.Now().UTC().Truncate(time.Hour).Add(-5 * time.Hour)
	rows, err := cosem.ReadProfileRange(cl, profile, cols[tc], from, from.Add(4*time.Hour), time.UTC)
	if err != nil {
		t.Fatalf("profile by range: %v", err)
	}
	if len(rows) == 0 {
		t.Fatalf("by range from %v: no rows", from)
	}
	_, tm := cosem.ProfileRow(rows[0], cols, cosem.RowScalers{Location: time.UTC})
	if !tm.Equal(from) {
		t.Errorf("by range from %v: first row at %v", from, tm)
	}
	t.Logf("by range from %v: %d rows, first at %v", from, len(rows), tm)
}

// Profile generic over low-level security on both links.
func TestProfileGeneric(t *testing.T) {
	s := needPeer(t)
	for _, l := range []link{overWrapper, overHDLC} {
		t.Run(l.String(), func(t *testing.T) {
			c := connect(t, s, l, 17, cosem.SecurityConfig{Authentication: "low", Password: "Gurux"}, "Gurux")
			readProfile(t, c, true)
		})
	}
}
