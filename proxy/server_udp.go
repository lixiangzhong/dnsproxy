package proxy

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"syscall"

	"github.com/AdguardTeam/dnsproxy/proxyutil"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
	"golang.org/x/sys/unix"
)

func (p *Proxy) createUDPListeners() error {
	n := runtime.NumCPU()
	if n > 1 {
		n--
	}

	reuselisten := func(a *net.UDPAddr) error {
		udpListen, err := p.udpCreate(a)
		if err != nil {
			return err
		}
		p.udpListen = append(p.udpListen, udpListen)
		return nil
	}

	for _, a := range p.UDPListenAddr {
		for i := 0; i < n; i++ {
			err := reuselisten(a)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

var lc = net.ListenConfig{
	Control: func(network string, address string, c syscall.RawConn) error {
		var err error
		c.Control(func(fd uintptr) {
			err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
			if err != nil {
				return
			}
			err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			if err != nil {
				return
			}
		})
		return err
	},
}

// udpCreate - create a UDP listening socket
func (p *Proxy) udpCreate(udpAddr *net.UDPAddr) (*net.UDPConn, error) {
	log.Info("Creating the UDP server socket")
	pc, err := lc.ListenPacket(context.Background(), "udp", udpAddr.String())
	if err != nil {
		return nil, fmt.Errorf("listening to udp socket: %w", err)
	}
	udpListen, ok := pc.(*net.UDPConn)
	if !ok {
		return nil, fmt.Errorf("listening to udp socket: %w", err)
	}
	if p.Config.UDPBufferSize > 0 {
		err = udpListen.SetReadBuffer(p.Config.UDPBufferSize)
		if err != nil {
			_ = udpListen.Close()
			return nil, fmt.Errorf("setting read udp buf size: %w", err)
		}
		err = udpListen.SetWriteBuffer(p.Config.UDPBufferSize)
		if err != nil {
			_ = udpListen.Close()
			return nil, fmt.Errorf("setting write udp buf size: %w", err)
		}
	}
	if c, err := udpListen.SyscallConn(); err == nil {
		c.Control(func(fd uintptr) {
			bufsize, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF)
			if err == nil {
				log.Info("UDP socket read buffer size: %d", bufsize)
			}
			bufsize, err = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF)
			if err == nil {
				log.Info("UDP socket write buffer size: %d", bufsize)
			}
		})
	}

	err = proxyutil.UDPSetOptions(udpListen)
	if err != nil {
		_ = udpListen.Close()

		return nil, fmt.Errorf("setting udp opts: %w", err)
	}

	log.Info("Listening to udp://%s", udpListen.LocalAddr())

	return udpListen, nil
}

// udpPacketLoop listens for incoming UDP packets.
//
// See also the comment on Proxy.requestGoroutinesSema.
func (p *Proxy) udpPacketLoop(conn *net.UDPConn, requestGoroutinesSema semaphore) {
	log.Info("Entering the UDP listener loop on %s", conn.LocalAddr())
	b := make([]byte, dns.MaxMsgSize)
	for {
		p.RLock()
		if !p.started {
			return
		}
		p.RUnlock()

		n, localIP, remoteAddr, err := proxyutil.UDPRead(conn, b, p.udpOOBSize)
		// documentation says to handle the packet even if err occurs, so do that first
		if n > 0 {
			// make a copy of all bytes because ReadFrom() will overwrite contents of b on next call
			// we need the contents to survive the call because we're handling them in goroutine

			packetPtr := p.bytesPool.Get().(*[]byte)
			packet := *packetPtr
			copy(packet[:n], b[:n])
			requestGoroutinesSema.acquire()
			go func() {
				p.udpHandlePacket(packet[:n], localIP, remoteAddr, conn)
				p.bytesPool.Put(packetPtr)
				requestGoroutinesSema.release()
			}()
		}
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				log.Debug("udpPacketLoop: connection closed")
			} else {
				log.Error("got error when reading from UDP listen: %s", err)
			}

			break
		}
	}
}

// udpHandlePacket processes the incoming UDP packet and sends a DNS response
func (p *Proxy) udpHandlePacket(packet []byte, localIP net.IP, remoteAddr *net.UDPAddr, conn *net.UDPConn) {
	log.Tracef("Start handling new UDP packet from %s", remoteAddr)

	req := &dns.Msg{}
	err := req.Unpack(packet)
	if err != nil {
		log.Error("unpacking udp packet: %s", err)

		return
	}

	d := p.newDNSContext(ProtoUDP, req)
	d.Addr = remoteAddr
	d.Conn = conn
	d.localIP = localIP

	err = p.handleDNSRequest(d)
	if err != nil {
		log.Tracef("error handling DNS (%s) request: %s", d.Proto, err)
	}
}

// Writes a response to the UDP client
func (p *Proxy) respondUDP(d *DNSContext) error {
	resp := d.Res

	if resp == nil {
		// Do nothing if no response has been written
		return nil
	}

	bytes, err := resp.Pack()
	if err != nil {
		return fmt.Errorf("packing message: %w", err)
	}

	conn := d.Conn.(*net.UDPConn)
	rAddr := d.Addr.(*net.UDPAddr)

	n, err := proxyutil.UDPWrite(bytes, conn, rAddr, d.localIP)
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			return nil
		}

		return fmt.Errorf("writing message: %w", err)
	}

	if n != len(bytes) {
		return fmt.Errorf("udpWrite() returned with %d != %d", n, len(bytes))
	}

	return nil
}
