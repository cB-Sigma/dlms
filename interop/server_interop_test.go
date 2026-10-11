// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"gitlab.com/circutor-library/gosem/pkg/axdr"

	"github.com/cB-Sigma/dlms/classes"
	dlmsserver "github.com/cB-Sigma/dlms/server"
)

// The client peer: the gurux-dlms package for Python at this version, in
// this image, running testdata/gurux_client.py against our server.
const (
	pyImage      = "python:3.12.10-slim"
	guruxPackage = "gurux-dlms==1.0.203"
)

var (
	pyOnce sync.Once
	pyName string
	pyErr  error
)

func needPython(t *testing.T) string {
	t.Helper()
	if os.Getenv("SIGMA_DLMS_INTEROP") != "1" {
		t.Skip("runs Gurux's DLMS client in Docker; set SIGMA_DLMS_INTEROP=1 to run")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not on PATH")
	}
	pyOnce.Do(func() {
		td, err := filepath.Abs("testdata")
		if err != nil {
			pyErr = err
			return
		}
		pyName = fmt.Sprintf("sigma-dlms-gurux-py-%d", os.Getpid())
		out, err := exec.Command("docker", "run", "-d", "--name", pyName, "--add-host", "host.docker.internal:host-gateway",
			"-v", td+":/sigma:ro", pyImage, "sleep", "3600").CombinedOutput()
		if err != nil {
			pyErr = fmt.Errorf("docker run: %v: %s", err, out)
			return
		}
		cleanup = append(cleanup, pyName)
		out, err = exec.Command("docker", "exec", pyName, "pip", "install", "--no-cache-dir", "--disable-pip-version-check",
			"--root-user-action=ignore", guruxPackage).CombinedOutput()
		if err != nil {
			pyErr = fmt.Errorf("pip install %s: %v: %s", guruxPackage, err, out)
		}
	})
	if pyErr != nil {
		t.Fatal(pyErr)
	}
	return pyName
}

// cleanup lists containers TestMain removes.
var cleanup []string

// serverListenAddr is where our server listens so that the container
// reaches it at host.docker.internal.
func serverListenAddr() string {
	if runtime.GOOS == "darwin" {
		return "127.0.0.1:0"
	}
	return "0.0.0.0:0"
}

type check struct {
	Check  string `json:"check"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

// guruxClient runs the client script against addr; a check that failed
// fails the test.
func guruxClient(t *testing.T, addr string, args ...string) map[string]check {
	t.Helper()
	name := needPython(t)
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	cmd := append([]string{"exec", name, "python", "-I", "/sigma/gurux_client.py", "--host", "host.docker.internal", "--port", port}, args...)
	var stdout, stderr bytes.Buffer
	c := exec.Command("docker", cmd...)
	c.Stdout, c.Stderr = &stdout, &stderr
	runErr := c.Run()
	got := map[string]check{}
	sc := bufio.NewScanner(&stdout)
	for sc.Scan() {
		var ck check
		if json.Unmarshal(sc.Bytes(), &ck) != nil {
			continue
		}
		got[ck.Check] = ck
		if ck.OK {
			t.Logf("PASS %s: %s", ck.Check, ck.Detail)
		} else {
			t.Errorf("FAIL %s: %s", ck.Check, ck.Detail)
		}
	}
	if runErr != nil {
		t.Errorf("gurux client: %v\n%s", runErr, stderr.String())
	}
	if _, ok := got["associate"]; !ok {
		t.Fatalf("the gurux client reported nothing\n%s", stderr.String())
	}
	return got
}

var (
	ifKey   = strings.Repeat("30", 16)
	ifAK    = strings.Repeat("31", 16)
	ifKey32 = strings.Repeat("32", 32)
	ifAK32  = strings.Repeat("33", 32)
)

// Gurux's client against our server with HLS-GMAC and authenticated and
// encrypted APDUs in security suites 0, 1 and 2, in general-glo and
// general-ded ciphering (Gurux's choice when general protection is
// negotiated) and in service-specific ciphering with the global and a
// dedicated key; the server counts the forms it opened.
func TestGuruxClientSuitesAndCiphering(t *testing.T) {
	needPython(t)
	s, w, h := ourServer(t, 50, false, false)
	type suite struct {
		n       string
		client  string
		key, ak string
	}
	for _, su := range []suite{{"0", "49", ifKey, ifAK}, {"1", "50", ifKey, ifAK}, {"2", "51", ifKey32, ifAK32}} {
		for _, form := range [][]string{nil, {"--dedicated"}, {"--service-specific"}, {"--service-specific", "--dedicated"}} {
			name := "suite" + su.n + "/general"
			if len(form) > 0 {
				name = "suite" + su.n + "/" + strings.Join(form, "")
			}
			t.Run(name, func(t *testing.T) {
				args := []string{"--iface", "wrapper", "--client", su.client, "--auth", "gmac", "--security", "authenc", "--suite", su.n,
					"--block-key", su.key, "--auth-key", su.ak, "--get", gClock, "--get", gVoltage, "--profile", gProfile}
				guruxClient(t, w, append(args, form...)...)
			})
		}
	}
	t.Run("hdlc/suite1", func(t *testing.T) {
		guruxClient(t, h, "--iface", "hdlc", "--client", "50", "--auth", "gmac", "--security", "authenc", "--suite", "1",
			"--block-key", ifKey, "--auth-key", ifAK, "--get", gClock, "--get", gVoltage)
	})
	st := s.Stats()
	t.Logf("protected requests opened: %d service-specific, %d general-glo, %d general-ded", st.ServiceSpecific, st.GeneralGlo, st.GeneralDed)
	if st.ServiceSpecific == 0 || st.GeneralGlo == 0 || st.GeneralDed == 0 {
		t.Errorf("a ciphering form was not used: %+v", st)
	}
}

// ourServer is a server package meter: register, clock, serial number,
// a writable data object, a profile of rows hourly entries ending now and
// a disconnect control; clients 16 (none), 32 (low, ABCDEFGH), 48
// (HLS mechanism 2), 49 (HLS-GMAC, suite 0, authenticated and encrypted).
func ourServer(t *testing.T, rows int, sn, gbt bool) (*dlmsserver.Server, string, string) {
	t.Helper()
	key, _ := hex.DecodeString(ifKey)
	ak, _ := hex.DecodeString(ifAK)
	key32, _ := hex.DecodeString(ifKey32)
	ak32, _ := hex.DecodeString(ifAK32)
	loc := time.UTC
	end := time.Now().UTC().Truncate(time.Hour)
	prof := &classes.ProfileGeneric{LN: "1.0.99.1.0.255", Location: loc, CapturePeriod: 3600, ProfileEntries: uint32(rows),
		CaptureObjects: []classes.CaptureObject{{Class: 8, LN: "0.0.1.0.0.255", Attr: 2}, {Class: 3, LN: "1.0.32.7.0.255", Attr: 2}}}
	for i := rows - 1; i >= 0; i-- {
		prof.Buffer = append(prof.Buffer, []*axdr.DlmsData{
			axdr.CreateAxdrOctetString(hex.EncodeToString(classes.DateTime(end.Add(-time.Duration(i)*time.Hour), loc))),
			axdr.CreateAxdrLongUnsigned(uint16(23000 + i%100)),
		})
	}
	s := &dlmsserver.Server{SystemTitle: []byte("SGMSRV01"), ShortNames: sn, GBT: gbt}
	s.Add(&classes.Register{LN: "1.0.32.7.0.255", Value: axdr.CreateAxdrLongUnsigned(23050), Scaler: -2, Unit: 35},
		&classes.Clock{LN: "0.0.1.0.0.255", Location: loc},
		&classes.Data{LN: "0.0.96.1.0.255", Value: axdr.CreateAxdrOctetString(hex.EncodeToString([]byte("SGM0001")))},
		&classes.Data{LN: "0.0.96.1.1.255", Value: axdr.CreateAxdrOctetString("")},
		&classes.DisconnectControl{LN: "0.0.96.3.10.255", OutputState: true, ControlState: 1, ControlMode: 1},
		prof)
	s.Associations = []*dlmsserver.Association{
		{ClientAddress: 16},
		{ClientAddress: 32, Mechanism: 1, Secret: []byte("ABCDEFGH")},
		{ClientAddress: 48, Mechanism: 2, Secret: []byte("UTILITYSECRET016")},
		{ClientAddress: 49, Mechanism: 5, Policy: 0x30, Key: key, AuthKey: ak},
		{ClientAddress: 50, Mechanism: 5, Policy: 0x30, Suite: 1, Key: key, AuthKey: ak},
		{ClientAddress: 51, Mechanism: 5, Policy: 0x30, Suite: 2, Key: key32, AuthKey: ak32},
	}
	w, err := s.ListenWrapper(serverListenAddr())
	if err != nil {
		t.Fatal(err)
	}
	h, err := s.ListenHDLC(serverListenAddr())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, w, h
}

func eachLink(t *testing.T, w, h string, f func(t *testing.T, iface, addr string)) {
	for _, iface := range []string{"wrapper", "hdlc"} {
		addr := w
		if iface == "hdlc" {
			addr = h
		}
		t.Run(iface, func(t *testing.T) { f(t, iface, addr) })
	}
}

const (
	gClock    = "8:0.0.1.0.0.255:2"
	gSerial   = "1:0.0.96.1.0.255:2"
	gVoltage  = "3:1.0.32.7.0.255:2"
	gScaler   = "3:1.0.32.7.0.255:3"
	gProfile  = "1.0.99.1.0.255"
	gBigWrite = "0.0.96.1.1.255:"
)

// Gurux's client against our server, logical names: every association,
// reads (the profile whole in blocks, by entry and by range), a write in
// blocks and an action.
func TestGuruxClientAgainstServer(t *testing.T) {
	needPython(t)
	s, w, h := ourServer(t, 400, false, false)
	big := strings.Repeat("A5", 1500)
	eachLink(t, w, h, func(t *testing.T, iface, addr string) {
		t.Run("public", func(t *testing.T) {
			guruxClient(t, addr, "--iface", iface, "--client", "16", "--get", gClock, "--get", gSerial)
		})
		t.Run("low", func(t *testing.T) {
			guruxClient(t, addr, "--iface", iface, "--client", "32", "--auth", "low", "--password", "ABCDEFGH",
				"--get", gClock, "--get", gVoltage, "--get", gScaler, "--profile", gProfile, "--range-hours", "6",
				"--set", gBigWrite+big, "--action", "70:0.0.96.3.10.255:1:0")
		})
		t.Run("hls-aes", func(t *testing.T) {
			guruxClient(t, addr, "--iface", iface, "--client", "48", "--auth", "hls", "--password", "UTILITYSECRET016",
				"--get", gClock, "--get", gVoltage)
		})
		t.Run("hls-gmac", func(t *testing.T) {
			guruxClient(t, addr, "--iface", iface, "--client", "49", "--auth", "gmac", "--security", "authenc",
				"--block-key", ifKey, "--auth-key", ifAK, "--get", gClock, "--get", gVoltage, "--profile", gProfile)
		})
	})
	if n := s.Stats().Blocks; n < 10 {
		t.Errorf("the server sent %d data blocks", n)
	}
}

// Gurux's client against our server with short names: the object list,
// reads (the profile whole: Gurux's short name client proposes no block
// transfer, so it comes in one APDU), a write, with low-level security
// and HLS mechanism 2.
//
// Not checked with this peer, because gurux-dlms 1.0.203 for Python fails
// in its own code: a ciphered short name reply_to_HLS_authentication (an
// assertion in getSNPdu), short name data blocks when block transfer is
// proposed (AttributeError: setTotalCount) and general block transfer
// (AttributeError: blockNumber). Those paths are checked with our own
// client (server package tests) and against Gurux's Java server.
func TestGuruxClientAgainstServerShortNames(t *testing.T) {
	needPython(t)
	_, w, h := ourServer(t, 300, true, false)
	eachLink(t, w, h, func(t *testing.T, iface, addr string) {
		t.Run("low", func(t *testing.T) {
			guruxClient(t, addr, "--sn", "--iface", iface, "--client", "32", "--auth", "low", "--password", "ABCDEFGH",
				"--get", gClock, "--get", gVoltage, "--get", gScaler, "--get", gSerial, "--set", gBigWrite+"BEEF", "--profile", gProfile)
		})
		t.Run("hls-aes", func(t *testing.T) {
			guruxClient(t, addr, "--sn", "--iface", iface, "--client", "48", "--auth", "hls", "--password", "UTILITYSECRET016",
				"--get", gClock, "--get", gVoltage)
		})
	})
}
