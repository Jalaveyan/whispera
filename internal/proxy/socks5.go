package proxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

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

// AuthHandler функция для проверки аутентификации
type AuthHandler func(username, password string) bool

// mapErrorToReplyCode converts generic errors to SOCKS5 reply codes
func mapErrorToReplyCode(err error) byte {
	if err == nil {
		return socks5ReplySuccess
	}

	// Check for specific network errors
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

// SOCKS5Server представляет SOCKS5 прокси сервер
type SOCKS5Server struct {
	listenAddr    string
	handler       func(net.Conn, string, uint16) error
	authHandler   AuthHandler          // Обработчик аутентификации (nil = NoAuth)
	packetHandler PacketHandler        // Обработчик UDP пакетов (nil = Drop)
	udpHandler    func(net.Conn) error // External UDP ASSOCIATE handler
	udpConn       *net.UDPConn         // UDP соединение для UDP ASSOCIATE
	udpAddr       *net.UDPAddr         // Адрес UDP сервера
	mu            sync.RWMutex
	log           *logger.Logger
}

// PacketHandler handles raw UDP packets from SOCKS5 clients
type PacketHandler func(data []byte, from net.Addr) error

// NewSOCKS5Server создает новый SOCKS5 сервер
func NewSOCKS5Server(addr string, handler func(net.Conn, string, uint16) error) *SOCKS5Server {
	return &SOCKS5Server{
		listenAddr: addr,
		handler:    handler,
		log:        logger.Module("socks5"),
	}
}

// SetAuthHandler устанавливает обработчик аутентификации
func (s *SOCKS5Server) SetAuthHandler(handler AuthHandler) {
	s.authHandler = handler
}

// SetUDPAddr устанавливает адрес для UDP ASSOCIATE
func (s *SOCKS5Server) SetUDPAddr(addr *net.UDPAddr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.udpAddr = addr
}

// SetUDPHandler sets the handler for UDP ASSOCIATE
func (s *SOCKS5Server) SetUDPHandler(h func(net.Conn) error) {
	s.udpHandler = h
}

// SetPacketHandler sets the handler for UDP packets
func (s *SOCKS5Server) SetPacketHandler(h PacketHandler) {
	s.packetHandler = h
}

// ListenAndServe запускает SOCKS5 сервер
func (s *SOCKS5Server) ListenAndServe() error {
	listener, err := net.Listen("tcp", s.listenAddr)
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

// handleConnection обрабатывает одно SOCKS5 подключение
func (s *SOCKS5Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	fmt.Printf("[SOCKS5] New connection from %s\n", conn.RemoteAddr())

	// SOCKS5 handshake
	if err := s.handleHandshake(conn); err != nil {
		fmt.Printf("[SOCKS5] Handshake failed: %v\n", err)
		s.log.Debug("Handshake failed: %v", err)
		return
	}

	// SOCKS5 request
	addr, port, err := s.handleRequest(conn)
	if err != nil {
		fmt.Printf("[SOCKS5] Request failed: %v\n", err)
		s.log.Debug("Request failed: %v", err)
		return
	}

	fmt.Printf("[SOCKS5] Request: addr=%s port=%d\n", addr, port)

	// Empty addr means UDP ASSOCIATE was handled internally (or via external handler)
	if addr == "" {
		fmt.Printf("[SOCKS5] UDP ASSOCIATE handled\n")
		// Keep connection alive for UDP relay (it monitors this connection)
		select {} // Block forever until connection closes
	}

	// Вызываем обработчик для проксирования
	if err := s.handler(conn, addr, port); err != nil {
		if err != io.EOF && err.Error() != "EOF" && !strings.Contains(err.Error(), "i/o timeout") && !strings.Contains(err.Error(), "use of closed network connection") {
			fmt.Printf("[SOCKS5] Handler failed: %v\n", err)
			s.log.Debug("Handler failed: %v", err)
		}
	}
}

// handleHandshake обрабатывает SOCKS5 handshake
func (s *SOCKS5Server) handleHandshake(conn net.Conn) error {
	// Читаем версию и количество методов
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

	// Читаем методы
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	// Выбираем метод (предпочитаем Username/Password если есть handler, иначе NoAuth)
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

	// Если есть auth handler, предпочитаем Username/Password
	if s.authHandler != nil && hasUsernamePass {
		selectedMethod = socks5MethodUsernamePass
	} else if hasNoAuth {
		selectedMethod = socks5MethodNoAuth
	}

	// Отправляем ответ
	response := []byte{socks5Version, selectedMethod}
	if _, err := conn.Write(response); err != nil {
		return err
	}

	if selectedMethod == socks5MethodNotAcceptable {
		return errors.New("no acceptable authentication method")
	}

	// Если выбран Username/Password, выполняем аутентификацию
	if selectedMethod == socks5MethodUsernamePass {
		if err := s.handleUsernamePasswordAuth(conn); err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}
	}

	return nil
}

// handleRequest обрабатывает SOCKS5 request
func (s *SOCKS5Server) handleRequest(conn net.Conn) (string, uint16, error) {
	// Читаем заголовок запроса
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", 0, err
	}

	// DEBUG: Log raw header bytes
	fmt.Printf("[SOCKS5] Raw header bytes: [%02x %02x %02x %02x] (VER=%d CMD=%d RSV=%d ATYP=%d)\n",
		header[0], header[1], header[2], header[3],
		header[0], header[1], header[2], header[3])

	if header[0] != socks5Version {
		return "", 0, fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}

	cmd := header[1]

	// Обрабатываем разные команды
	switch cmd {
	case socks5CmdConnect:
		// Обрабатывается ниже
	case socks5CmdUDP:
		// UDP ASSOCIATE
		if s.udpHandler != nil {
			// Use external handler
			// Check ATYP (header[3]) to skip address parsing here if needed, or pass control
			// Standard SOCKS5: UDP ASSOCIATE sends address/port of client. We usually ignore it.
			// We need to consume the address/port bytes first.
			atyp := header[3]
			// Consume address/port logic (replicated from below)
			switch atyp {
			case socks5ATYPIPv4:
				io.CopyN(io.Discard, conn, 4)
			case socks5ATYPIPv6:
				io.CopyN(io.Discard, conn, 16)
			case socks5ATYPDomain:
				lenBuf := make([]byte, 1)
				io.ReadFull(conn, lenBuf)
				io.CopyN(io.Discard, conn, int64(lenBuf[0]))
			}
			io.CopyN(io.Discard, conn, 2) // Port

			// Call external handler
			if err := s.udpHandler(conn); err != nil {
				s.sendReply(conn, mapErrorToReplyCode(err), nil, 0)
				return "", 0, err
			}
			return "", 0, nil
		}
		// Fallback to internal
		return s.handleUDPAssociate(conn, header[3])
	case socks5CmdBind:
		// BIND не поддерживается
		s.sendReply(conn, socks5ReplyCommandNotSupported, nil, 0)
		return "", 0, fmt.Errorf("BIND command not supported")
	default:
		s.sendReply(conn, socks5ReplyCommandNotSupported, nil, 0)
		return "", 0, fmt.Errorf("unsupported command: %d", cmd)
	}

	// Читаем адрес
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

	// Читаем порт
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", 0, err
	}
	port = binary.BigEndian.Uint16(portBuf)

	// Обрабатываем разные команды
	switch cmd {
	case socks5CmdConnect:
		// Отправляем успешный ответ с адресом клиента
		// Определяем тип адреса для ответа
		var replyAddr []byte
		var replyPort uint16 = 0 // Порт не используется для CONNECT

		if tcpAddr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
			if ip4 := tcpAddr.IP.To4(); ip4 != nil {
				// IPv4
				replyAddr = append([]byte{socks5ATYPIPv4}, ip4...)
			} else if ip6 := tcpAddr.IP.To16(); ip6 != nil {
				// IPv6
				replyAddr = append([]byte{socks5ATYPIPv6}, ip6...)
			}
		}

		// Если не удалось определить адрес, используем заглушку
		if replyAddr == nil {
			replyAddr = []byte{socks5ATYPIPv4, 0, 0, 0, 0}
		}

		if err := s.sendReply(conn, socks5ReplySuccess, replyAddr, replyPort); err != nil {
			return "", 0, err
		}

		return addr, port, nil

	case socks5CmdUDP:
		// UDP ASSOCIATE
		return s.handleUDPAssociate(conn, atyp)

	case socks5CmdBind:
		// BIND не поддерживается
		s.sendReply(conn, socks5ReplyCommandNotSupported, nil, 0)
		return "", 0, fmt.Errorf("BIND command not supported")

	default:
		s.sendReply(conn, socks5ReplyCommandNotSupported, nil, 0)
		return "", 0, fmt.Errorf("unsupported command: %d", cmd)
	}
}

// sendReply отправляет SOCKS5 reply
func (s *SOCKS5Server) sendReply(conn net.Conn, reply byte, addr []byte, port uint16) error {
	response := []byte{socks5Version, reply, 0} // версия, reply, зарезервировано

	if len(addr) > 0 {
		// Добавляем адрес (уже содержит ATYP)
		response = append(response, addr...)
		// Добавляем порт
		portBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(portBuf, port)
		response = append(response, portBuf...)
	} else {
		// IPv4 заглушка (ATYP + 4 байта IP + 2 байта порта)
		response = append(response, socks5ATYPIPv4, 0, 0, 0, 0)
		portBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(portBuf, port)
		response = append(response, portBuf...)
	}

	_, err := conn.Write(response)
	return err
}

// handleUsernamePasswordAuth обрабатывает Username/Password аутентификацию
func (s *SOCKS5Server) handleUsernamePasswordAuth(conn net.Conn) error {
	// Читаем версию (должна быть 0x01)
	version := make([]byte, 1)
	if _, err := io.ReadFull(conn, version); err != nil {
		return err
	}
	if version[0] != 0x01 {
		return fmt.Errorf("unsupported auth version: %d", version[0])
	}

	// Читаем длину username
	usernameLen := make([]byte, 1)
	if _, err := io.ReadFull(conn, usernameLen); err != nil {
		return err
	}

	// Читаем username
	username := make([]byte, int(usernameLen[0]))
	if _, err := io.ReadFull(conn, username); err != nil {
		return err
	}

	// Читаем длину password
	passwordLen := make([]byte, 1)
	if _, err := io.ReadFull(conn, passwordLen); err != nil {
		return err
	}

	// Читаем password
	password := make([]byte, int(passwordLen[0]))
	if _, err := io.ReadFull(conn, password); err != nil {
		return err
	}

	// Проверяем аутентификацию
	if s.authHandler == nil || !s.authHandler(string(username), string(password)) {
		// Отправляем ошибку аутентификации
		response := []byte{0x01, 0xFF} // версия, статус (0xFF = failure)
		if _, err := conn.Write(response); err != nil {
			return err
		}
		return errors.New("authentication failed")
	}

	// Отправляем успешный ответ
	response := []byte{0x01, 0x00} // версия, статус (0x00 = success)
	if _, err := conn.Write(response); err != nil {
		return err
	}

	return nil
}

// handleUDPAssociate обрабатывает UDP ASSOCIATE команду
func (s *SOCKS5Server) handleUDPAssociate(conn net.Conn, atyp byte) (string, uint16, error) {
	// Read the rest of the request (address and port)
	// We need to read them even though we don't use them
	// This is required by SOCKS5 protocol

	// Read address based on ATYP (already read in header)
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

	// Read port
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		s.sendReply(conn, socks5ReplyGeneralFailure, nil, 0)
		return "", 0, err
	}

	// Create UDP relay socket
	udpListener, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 0, // Let system choose port
	})
	if err != nil {
		s.sendReply(conn, socks5ReplyGeneralFailure, nil, 0)
		return "", 0, fmt.Errorf("failed to create UDP listener: %w", err)
	}

	// Get the address we're listening on
	localAddr := udpListener.LocalAddr().(*net.UDPAddr)

	// Send reply with our UDP relay address
	replyAddr := append([]byte{socks5ATYPIPv4}, localAddr.IP.To4()...)
	port := uint16(localAddr.Port)

	if err := s.sendReply(conn, socks5ReplySuccess, replyAddr, port); err != nil {
		udpListener.Close()
		return "", 0, err
	}

	s.log.Debug("UDP ASSOCIATE: relay listening on %s", localAddr.String())

	// Start UDP relay in background
	go s.handleUDPRelay(udpListener, conn)

	// Return empty address to signal this is handled internally
	// The caller should NOT call handler for UDP ASSOCIATE
	return "", 0, nil
}

// handleUDPRelay handles the UDP relay for UDP ASSOCIATE
func (s *SOCKS5Server) handleUDPRelay(udpListener *net.UDPConn, tcpConn net.Conn) {
	defer udpListener.Close()

	// Map to track client addresses
	clientAddr := (*net.UDPAddr)(nil)

	buf := make([]byte, 65535)

	// Set read deadline based on TCP connection
	go func() {
		// Monitor TCP connection - when it closes, shutdown UDP relay
		oneByte := make([]byte, 1)
		tcpConn.Read(oneByte) // This will block until connection closes
		udpListener.Close()
	}()

	for {
		n, addr, err := udpListener.ReadFromUDP(buf)
		if err != nil {
			return
		}

		// Remember client address
		if clientAddr == nil {
			clientAddr = addr
		}

		// Parse SOCKS5 UDP header
		// +----+------+------+----------+----------+----------+
		// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
		// +----+------+------+----------+----------+----------+
		// | 2  |  1   |  1   | Variable |    2     | Variable |
		// +----+------+------+----------+----------+----------+

		if n < 10 { // Minimum header size
			continue
		}

		// RSV (2 bytes) + FRAG (1 byte)
		frag := buf[2]
		if frag != 0 {
			// Fragmentation not supported
			continue
		}

		// Check for custom handler
		if s.packetHandler != nil {
			if err := s.packetHandler(buf[:n], addr); err != nil {
				s.log.Debug("Packet handler error: %v", err)
			}
			continue
		}

		// SECURITY: Block direct UDP relay to prevent leaks.
		// If no packet handler is set (e.g. tunneling), we drop the packet.
		// Original direct dial logic removed.
		s.log.Debug("Dropped UDP packet from %s (direct relay disabled)", addr)
	}
}
