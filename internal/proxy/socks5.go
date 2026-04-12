package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"whispera/internal/logger"
)

const (
	socks5Version = 0x05

	socks5MethodNoAuth        = 0x00
	socks5MethodUsernamePass  = 0x02
	socks5MethodNotAcceptable = 0xFF

	socks5CmdConnect = 0x01
	socks5CmdBind    = 0x02
	socks5CmdUDP     = 0x03

	socks5ATYPIPv4   = 0x01
	socks5ATYPIPv6   = 0x04
	socks5ATYPDomain = 0x03

	socks5ReplySuccess                 = 0x00
	socks5ReplyGeneralFailure          = 0x01
	socks5ReplyConnectionNotAllowed    = 0x02
	socks5ReplyNetworkUnreachable      = 0x03
	socks5ReplyHostUnreachable         = 0x04
	socks5ReplyConnectionRefused       = 0x05
	socks5ReplyTTLExpired              = 0x06
	socks5ReplyCommandNotSupported     = 0x07
	socks5ReplyAddressTypeNotSupported = 0x08
)

type AuthHandler func(username, password string) bool

func mapErrorToReplyCode(err error) byte {
	if err == nil {
		return socks5ReplySuccess
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return socks5ReplyTTLExpired
		}
	}

	msg := err.Error()
	switch msg {
	case "connection refused":
		return socks5ReplyConnectionRefused
	case "network unreachable":
		return socks5ReplyNetworkUnreachable
	case "host unreachable":
		return socks5ReplyHostUnreachable
	case "permission denied":
		return socks5ReplyConnectionNotAllowed
	}

	return socks5ReplyGeneralFailure
}

type SOCKS5Server struct {
	listenAddr      string
	handler         func(net.Conn, string, uint16) error
	authHandler     AuthHandler
	packetHandler   PacketHandler
	udpRelayHandler UDPRelayHandler
	udpHandler      func(net.Conn) error
	udpConn         *net.UDPConn
	udpAddr         *net.UDPAddr
	mu              sync.RWMutex
	log             *logger.Logger
}

type PacketHandler func(data []byte, from net.Addr) error

type UDPRelayHandler func(udpConn *net.UDPConn, tcpConn net.Conn)

func NewSOCKS5Server(addr string, handler func(net.Conn, string, uint16) error) *SOCKS5Server {
	return &SOCKS5Server{
		listenAddr: addr,
		handler:    handler,
		log:        logger.Module("socks5"),
	}
}

func (s *SOCKS5Server) SetAuthHandler(handler AuthHandler) {
	s.authHandler = handler
}

func (s *SOCKS5Server) SetUDPAddr(addr *net.UDPAddr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.udpAddr = addr
}

func (s *SOCKS5Server) SetUDPHandler(h func(net.Conn) error) {
	s.udpHandler = h
}

func (s *SOCKS5Server) SetPacketHandler(h PacketHandler) {
	s.packetHandler = h
}

func (s *SOCKS5Server) SetUDPRelayHandler(h UDPRelayHandler) {
	s.udpRelayHandler = h
}

func (s *SOCKS5Server) ListenAndServe() error {
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.listenAddr, err)
	}
	defer listener.Close()

	s.log.Info("✅ Server listening on %s - ready to accept connections", s.listenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			s.log.Error("Failed to accept connection: %v", err)
			continue
		}

		go s.handleConnection(conn)
	}
}

func (s *SOCKS5Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(30 * time.Second))

	fmt.Printf("[SOCKS5] New connection from %s\n", conn.RemoteAddr())

	if err := s.handleHandshake(conn); err != nil {
		fmt.Printf("[SOCKS5] Handshake failed: %v\n", err)
		s.log.Debug("Handshake failed: %v", err)
		return
	}

	addr, port, err := s.handleRequest(conn)
	if err != nil {
		fmt.Printf("[SOCKS5] Request failed: %v\n", err)
		s.log.Debug("Request failed: %v", err)
		return
	}

	conn.SetDeadline(time.Time{})

	fmt.Printf("[SOCKS5] Request: addr=%s port=%d\n", addr, port)

	if addr == "" {
		fmt.Printf("[SOCKS5] UDP ASSOCIATE handled\n")
		buf := make([]byte, 1)
		conn.Read(buf)
		return
	}

	if err := s.handler(conn, addr, port); err != nil {
		if err != io.EOF && err.Error() != "EOF" && !strings.Contains(err.Error(), "i/o timeout") && !strings.Contains(err.Error(), "use of closed network connection") {
			fmt.Printf("[SOCKS5] Handler failed: %v\n", err)
			s.log.Debug("Handler failed: %v", err)
		}
	}
}

func (s *SOCKS5Server) handleHandshake(conn net.Conn) error {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}

	if buf[0] != socks5Version {
		return fmt.Errorf("unsupported SOCKS version: %d", buf[0])
	}

	nMethods := int(buf[1])
	if nMethods == 0 {
		return errors.New("no authentication methods")
	}

	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	selectedMethod := byte(socks5MethodNotAcceptable)
	hasNoAuth := false
	hasUsernamePass := false

	for _, method := range methods {
		if method == socks5MethodNoAuth {
			hasNoAuth = true
		}
		if method == socks5MethodUsernamePass {
			hasUsernamePass = true
		}
	}

	if s.authHandler != nil {
		if hasUsernamePass {
			selectedMethod = socks5MethodUsernamePass
		}
	} else if hasNoAuth {
		selectedMethod = socks5MethodNoAuth
	}

	response := []byte{socks5Version, selectedMethod}
	if _, err := conn.Write(response); err != nil {
		return err
	}

	if selectedMethod == socks5MethodNotAcceptable {
		return errors.New("no acceptable authentication method")
	}

	if selectedMethod == socks5MethodUsernamePass {
		if err := s.handleUsernamePasswordAuth(conn); err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}
	}

	return nil
}

func (s *SOCKS5Server) handleRequest(conn net.Conn) (string, uint16, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", 0, err
	}

	fmt.Printf("[SOCKS5] Raw header bytes: [%02x %02x %02x %02x] (VER=%d CMD=%d RSV=%d ATYP=%d)\n",
		header[0], header[1], header[2], header[3],
		header[0], header[1], header[2], header[3])

	if header[0] != socks5Version {
		return "", 0, fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}

	cmd := header[1]

	switch cmd {
	case socks5CmdConnect:
	case socks5CmdUDP:
		if s.udpHandler != nil {
			atyp := header[3]
			switch atyp {
			case socks5ATYPIPv4:
				io.CopyN(io.Discard, conn, 4)
			case socks5ATYPIPv6:
				io.CopyN(io.Discard, conn, 16)
			case socks5ATYPDomain:
				lenBuf := make([]byte, 1)
				_, _ = io.ReadFull(conn, lenBuf)
				_, _ = io.CopyN(io.Discard, conn, int64(lenBuf[0]))
			}
			io.CopyN(io.Discard, conn, 2)

			if err := s.udpHandler(conn); err != nil {
				s.sendReply(conn, mapErrorToReplyCode(err), nil, 0)
				return "", 0, err
			}
			return "", 0, nil
		}
		return s.handleUDPAssociate(conn, header[3])
	case socks5CmdBind:
		s.sendReply(conn, socks5ReplyCommandNotSupported, nil, 0)
		return "", 0, fmt.Errorf("BIND command not supported")
	default:
		s.sendReply(conn, socks5ReplyCommandNotSupported, nil, 0)
		return "", 0, fmt.Errorf("unsupported command: %d", cmd)
	}

	atyp := header[3]
	var addr string
	var port uint16

	switch atyp {
	case socks5ATYPIPv4:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", 0, err
		}
		addr = net.IP(ip).String()

	case socks5ATYPIPv6:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return "", 0, err
		}
		addr = net.IP(ip).String()

	case socks5ATYPDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", 0, err
		}
		domainLen := int(lenBuf[0])
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", 0, err
		}
		addr = string(domain)

	default:
		s.sendReply(conn, socks5ReplyAddressTypeNotSupported, nil, 0)
		return "", 0, fmt.Errorf("unsupported address type: %d", atyp)
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", 0, err
	}
	port = binary.BigEndian.Uint16(portBuf)

	switch cmd {
	case socks5CmdConnect:
		var replyAddr []byte
		var replyPort uint16 = 0

		if tcpAddr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
			if ip4 := tcpAddr.IP.To4(); ip4 != nil {
				replyAddr = append([]byte{socks5ATYPIPv4}, ip4...)
			} else if ip6 := tcpAddr.IP.To16(); ip6 != nil {
				replyAddr = append([]byte{socks5ATYPIPv6}, ip6...)
			}
		}

		if replyAddr == nil {
			replyAddr = []byte{socks5ATYPIPv4, 0, 0, 0, 0}
		}

		if err := s.sendReply(conn, socks5ReplySuccess, replyAddr, replyPort); err != nil {
			return "", 0, err
		}

		return addr, port, nil

	case socks5CmdUDP:
		return s.handleUDPAssociate(conn, atyp)

	case socks5CmdBind:
		s.sendReply(conn, socks5ReplyCommandNotSupported, nil, 0)
		return "", 0, fmt.Errorf("BIND command not supported")

	default:
		s.sendReply(conn, socks5ReplyCommandNotSupported, nil, 0)
		return "", 0, fmt.Errorf("unsupported command: %d", cmd)
	}
}

func (s *SOCKS5Server) sendReply(conn net.Conn, reply byte, addr []byte, port uint16) error {
	response := []byte{socks5Version, reply, 0}

	if len(addr) > 0 {
		response = append(response, addr...)
		portBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(portBuf, port)
		response = append(response, portBuf...)
	} else {
		response = append(response, socks5ATYPIPv4, 0, 0, 0, 0)
		portBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(portBuf, port)
		response = append(response, portBuf...)
	}

	_, err := conn.Write(response)
	return err
}

func (s *SOCKS5Server) handleUsernamePasswordAuth(conn net.Conn) error {
	version := make([]byte, 1)
	if _, err := io.ReadFull(conn, version); err != nil {
		return err
	}
	if version[0] != 0x01 {
		return fmt.Errorf("unsupported auth version: %d", version[0])
	}

	usernameLen := make([]byte, 1)
	if _, err := io.ReadFull(conn, usernameLen); err != nil {
		return err
	}

	username := make([]byte, int(usernameLen[0]))
	if _, err := io.ReadFull(conn, username); err != nil {
		return err
	}

	passwordLen := make([]byte, 1)
	if _, err := io.ReadFull(conn, passwordLen); err != nil {
		return err
	}

	password := make([]byte, int(passwordLen[0]))
	if _, err := io.ReadFull(conn, password); err != nil {
		return err
	}

	if s.authHandler == nil || !s.authHandler(string(username), string(password)) {
		response := []byte{0x01, 0xFF}
		if _, err := conn.Write(response); err != nil {
			return err
		}
		return errors.New("authentication failed")
	}

	response := []byte{0x01, 0x00}
	if _, err := conn.Write(response); err != nil {
		return err
	}

	return nil
}

func (s *SOCKS5Server) handleUDPAssociate(conn net.Conn, atyp byte) (string, uint16, error) {
	switch atyp {
	case socks5ATYPIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			s.sendReply(conn, mapErrorToReplyCode(err), nil, 0)
			return "", 0, err
		}
	case socks5ATYPIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			s.sendReply(conn, mapErrorToReplyCode(err), nil, 0)
			return "", 0, err
		}
	case socks5ATYPDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			s.sendReply(conn, mapErrorToReplyCode(err), nil, 0)
			return "", 0, err
		}
		domain := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(conn, domain); err != nil {
			s.sendReply(conn, mapErrorToReplyCode(err), nil, 0)
			return "", 0, err
		}
	default:
		s.sendReply(conn, socks5ReplyAddressTypeNotSupported, nil, 0)
		return "", 0, fmt.Errorf("unsupported address type: %d", atyp)
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		s.sendReply(conn, socks5ReplyGeneralFailure, nil, 0)
		return "", 0, err
	}

	udpListener, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 0,
	})
	if err != nil {
		s.sendReply(conn, socks5ReplyGeneralFailure, nil, 0)
		return "", 0, fmt.Errorf("failed to create UDP listener: %w", err)
	}

	localAddr := udpListener.LocalAddr().(*net.UDPAddr)

	replyAddr := append([]byte{socks5ATYPIPv4}, localAddr.IP.To4()...)
	port := uint16(localAddr.Port)

	if err := s.sendReply(conn, socks5ReplySuccess, replyAddr, port); err != nil {
		udpListener.Close()
		return "", 0, err
	}

	s.log.Debug("UDP ASSOCIATE: relay listening on %s", localAddr.String())

	if s.udpRelayHandler != nil {
		go s.udpRelayHandler(udpListener, conn)
	} else {
		go s.handleUDPRelay(udpListener, conn)
	}

	return "", 0, nil
}

func (s *SOCKS5Server) handleUDPRelay(udpListener *net.UDPConn, tcpConn net.Conn) {
	defer udpListener.Close()

	clientAddr := (*net.UDPAddr)(nil)

	buf := make([]byte, 65535)

	go func() {
		oneByte := make([]byte, 1)
		tcpConn.Read(oneByte)
		udpListener.Close()
	}()

	for {
		n, addr, err := udpListener.ReadFromUDP(buf)
		if err != nil {
			return
		}

		if clientAddr == nil {
			clientAddr = addr
		}

		if n < 10 {
			continue
		}

		frag := buf[2]
		if frag != 0 {
			continue
		}

		if s.packetHandler != nil {
			if err := s.packetHandler(buf[:n], addr); err != nil {
				s.log.Debug("Packet handler error: %v", err)
			}
			continue
		}

		s.log.Debug("Dropped UDP packet from %s (direct relay disabled)", addr)
	}
}
