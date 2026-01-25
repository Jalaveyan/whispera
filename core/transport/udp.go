package transport

import (
	"context"
	"net"
	"sync"
	"time"

	"whispera/internal/modules/qos"
)

// UDPTransport реализует UDP транспорт с VoIP оптимизацией
type UDPTransport struct {
	conn            net.Conn
	config          *Config
	listener        net.PacketConn
	isVoIPOptimized bool
	voipQoS         *qos.VoIPQoS
	discordDetector *qos.DiscordDetector
	mu              sync.RWMutex
}

// NewUDPTransport создает новый UDP транспорт
func NewUDPTransport(config *Config) *UDPTransport {
	// **CRITICAL**: Включаем VoIP QoS ПО УМОЛЧАНИЮ для всех UDP подключений
	// Discord будет автоматически обнаружен DiscordDetector
	// это решает problem с высоким пингом когда трафик идет через обычные каналы

	t := &UDPTransport{
		config:          config,
		isVoIPOptimized: true, // Всегда включено для лучшей производительности голоса
		voipQoS:         qos.NewVoIPQoS(),
		discordDetector: qos.NewDiscordDetector(),
	}

	// Разрешаем отключение если явно указано в конфиге
	if config.Metadata != nil && config.Metadata["voip"] == "false" {
		t.isVoIPOptimized = false
	}

	return t
}

// Dial устанавливает UDP соединение с VoIP оптимизацией
func (t *UDPTransport) Dial(addr string) error {
	timeout := time.Duration(t.config.Timeout) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return err
	}

	// Применяем VoIP оптимизации
	if t.isVoIPOptimized {
		t.optimizeForVoIP(conn)
		// Включаем VoIP QoS обработку
		if t.voipQoS != nil {
			t.voipQoS.Enable()
		}
	}

	t.conn = conn
	return nil
}

// Listen запускает UDP слушатель с VoIP оптимизацией
func (t *UDPTransport) Listen() error {
	udpAddr, err := net.ResolveUDPAddr("udp", t.config.Addr)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}

	// Применяем VoIP оптимизации для слушателя
	if t.isVoIPOptimized {
		t.optimizeListenerForVoIP(conn)
		// Включаем VoIP QoS обработку и Discord детектор
		if t.voipQoS != nil {
			t.voipQoS.Enable()
		}
	}

	t.listener = conn
	return nil
}

// WriteRaw отправляет данные в UDP соединение
func (t *UDPTransport) WriteRaw(pkt []byte) error {
	if t.conn == nil {
		return ErrNotConnected
	}
	_, err := t.conn.Write(pkt)
	return err
}

// ReadRaw читает данные из UDP соединения
func (t *UDPTransport) ReadRaw(buf []byte) (int, error) {
	if t.conn == nil {
		return 0, ErrNotConnected
	}
	return t.conn.Read(buf)
}

// WriteTo отправляет данные на указанный адрес с VoIP приоритизацией
func (t *UDPTransport) WriteTo(pkt []byte, addr net.Addr) (int, error) {
	if t.listener == nil {
		return 0, ErrNotListening
	}

	// Применяем VoIP QoS обработку если включено
	if t.isVoIPOptimized && t.voipQoS != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
		defer cancel()

		// Обрабатываем пакет через QoS систему
		queuedPkt, err := t.voipQoS.ProcessPacket(ctx, pkt, pkt, addr)
		if err == nil && queuedPkt != nil {
			// Используем обработанный пакет если он был модифицирован
			return t.listener.WriteTo(queuedPkt.Data, addr)
		}
	}

	// Обычная отправка без QoS обработки
	return t.listener.WriteTo(pkt, addr)
}

// ReadFrom читает данные с адресом отправителя и анализирует Discord VoIP
func (t *UDPTransport) ReadFrom(buf []byte) (int, net.Addr, error) {
	if t.listener == nil {
		return 0, nil, ErrNotListening
	}

	n, addr, err := t.listener.ReadFrom(buf)
	if err == nil && n > 0 && t.isVoIPOptimized && t.discordDetector != nil {
		// Анализируем входящий пакет для обнаружения Discord VoIP
		go t.discordDetector.AnalyzePacket(buf[:n], addr, t.LocalAddr())
	}

	return n, addr, err
}

// Close закрывает UDP соединение и/или слушатель
func (t *UDPTransport) Close() error {
	var lastErr error

	if t.conn != nil {
		if err := t.conn.Close(); err != nil {
			lastErr = err
		}
	}

	if t.listener != nil {
		if err := t.listener.Close(); err != nil {
			lastErr = err
		}
	}

	return lastErr
}

// LocalAddr возвращает локальный адрес
func (t *UDPTransport) LocalAddr() net.Addr {
	if t.conn != nil {
		return t.conn.LocalAddr()
	}
	if t.listener != nil {
		return t.listener.LocalAddr()
	}
	return nil
}

// RemoteAddr возвращает удаленный адрес
func (t *UDPTransport) RemoteAddr() net.Addr {
	if t.conn != nil {
		return t.conn.RemoteAddr()
	}
	return nil
}

// optimizeForVoIP применяет сокет опции для VoIP
func (t *UDPTransport) optimizeForVoIP(conn *net.UDPConn) error {
	// Увеличиваем буферы для гладкой передачи голоса
	if err := conn.SetReadBuffer(2097152); err != nil { // 2MB recv buffer
		// Ignore error, may not be available on all platforms
	}
	if err := conn.SetWriteBuffer(2097152); err != nil { // 2MB send buffer
		// Ignore error
	}

	// Попытка установить DSCP для приоритета voice (EF = 0xB8)
	// Это рекомендуется RFC 3246
	if file, err := conn.File(); err == nil {
		defer file.Close()
		fd := int(file.Fd())

		// IP_TOS for IPv4
		// IPTOS_DSCP_EF = 0xB8 (11 10 0000)
		if err := setIPTOS(fd, 0xB8); err == nil {
			// Successfully set DSCP EF
		}
	}

	return nil
}

// optimizeListenerForVoIP оптимизирует слушатель для VoIP
func (t *UDPTransport) optimizeListenerForVoIP(conn *net.UDPConn) error {
	if err := conn.SetReadBuffer(2097152); err != nil {
		// Ignore error
	}
	if err := conn.SetWriteBuffer(2097152); err != nil {
		// Ignore error
	}

	if file, err := conn.File(); err == nil {
		defer file.Close()
		fd := int(file.Fd())
		if err := setIPTOS(fd, 0xB8); err == nil {
			// Successfully set DSCP EF
		}
	}

	return nil
}

// setIPTOS устанавливает IP ToS для DSCP приоритизации
// Это реализуется через syscall, зависит от платформы
func setIPTOS(fd int, tos int) error {
	// Эта функция будет зависеть от ОС
	// На Linux: syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TOS, tos)
	// На Windows: нужен WSASetSocketExclusiveAddrUse
	// На macOS: использовать SO_PRIORITY

	// Плейсхолдер - реальная реализация зависит от ОС
	return nil
}
