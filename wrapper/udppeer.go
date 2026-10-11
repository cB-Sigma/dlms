package wrapper

import (
	"fmt"
	"net"
	"time"
)

// udpPeer is the UDP side of the wrapper to one meter: an unconnected
// socket that sends to the meter and takes datagrams from the meter's IP
// address from any port. A connected socket would hear only the exact
// port it sent to, and some meters and modems answer from another; the
// wrapper ports of each answer are checked as before (read).
type udpPeer struct {
	*net.UDPConn
	remote *net.UDPAddr
}

func dialUDP(address string, timeout time.Duration) (net.Conn, error) {
	ra, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}
	local := &net.UDPAddr{}
	if ra.IP.To4() == nil {
		local.IP = net.IPv6unspecified
	}
	pc, err := net.ListenUDP("udp", local)
	if err != nil {
		return nil, fmt.Errorf("binding a UDP socket for %s: %w", address, err)
	}
	return &udpPeer{UDPConn: pc, remote: ra}, nil
}

func (u *udpPeer) Read(b []byte) (int, error) {
	for {
		n, a, err := u.UDPConn.ReadFromUDP(b)
		if err != nil {
			return n, err
		}
		if a.IP.Equal(u.remote.IP) {
			return n, nil
		}
	}
}

func (u *udpPeer) Write(b []byte) (int, error) { return u.UDPConn.WriteToUDP(b, u.remote) }

func (u *udpPeer) RemoteAddr() net.Addr { return u.remote }
