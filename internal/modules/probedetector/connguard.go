package probedetector

// ConnGuard — защита TCP-слушателей от CPU-выжигающих атак:
//
//  1. Per-IP rate limit новых соединений (лимит открытия)
//  2. First-bytes fast-reject: если первые байты не соответствуют
//     ни одному нашему протоколу — соединение закрывается немедленно,
//     до любой криптографической обработки.
//  3. Connection budget: если в очереди слишком много pending-соединений
//     от одного IP — новые отклоняются сразу.
//
// Цель атаки: цензор захватывает UDP-пакеты (QUIC/obfs4/WireGuard),
// оборачивает их в TCP и шлёт на наш сервер. Сервер пытается
// разобрать каждый кадр → расходует CPU на декодирование мусора.

import (
	"net"
	"sync"
	"time"
)

// KnownMagics — допустимые первые байты входящего TCP-соединения.
// Добавляйте новые транспорты сюда по мере их появления.
var KnownMagics = [][]byte{
	// TLS record layer (любая версия): 0x16 0x03 {0x00..0x04}
	{0x16, 0x03},
	// HTTP CONNECT / GET / POST / ...
	[]byte("CON"), []byte("GET"), []byte("POS"), []byte("PUT"),
	[]byte("DEL"), []byte("HEA"), []byte("OPT"), []byte("PAT"),
	// HTTP/2 connection preface
	[]byte("PRI"),
	// Whispera handshake magic byte (0x57 = 'W')
	{0x57},
	// Shadowsocks-over-TCP: первый байт может быть чем угодно (зашифровано),
	// поэтому для SS-транспорта ConnGuard нужно отключать (см. Bypass()).
	// WebSocket upgrade обёрнут в HTTP — уже покрыт выше.
}

const (
	// MaxConnsPerIPPerSec — максимум новых соединений с одного IP в секунду.
	// Легитимный клиент открывает 1-2 соединения; DPI-инжекция — десятки.
	MaxConnsPerIPPerSec = 10

	// MaxPendingPerIP — максимум одновременных незавершённых handshake с одного IP.
	MaxPendingPerIP = 5

	// FirstBytesDeadline — максимальное время ожидания первых байт.
	// Нужно короткое значение, чтобы idle-сокеты не висели долго.
	FirstBytesDeadline = 300 * time.Millisecond

	// MinFirstBytes — минимум байт для валидации.
	MinFirstBytes = 2
)

// ipBucket хранит состояние для одного IP.
type ipBucket struct {
	mu       sync.Mutex
	opens    []time.Time // временные метки открытых соединений за последнюю секунду
	pending  int         // текущих незавершённых соединений
}

// ConnGuard обеспечивает быструю защиту на уровне Accept().
type ConnGuard struct {
	mu      sync.RWMutex
	buckets map[string]*ipBucket

	// AllowMagics — если false, first-bytes проверка не выполняется
	// (полезно для шифрованных транспортов без фиксированного magic).
	CheckMagics bool

	cleanStop chan struct{}
}

// NewConnGuard создаёт новый ConnGuard. checkMagics=true включает
// проверку первых байт (отключить для Shadowsocks / полностью
// случайных транспортов).
func NewConnGuard(checkMagics bool) *ConnGuard {
	g := &ConnGuard{
		buckets:     make(map[string]*ipBucket),
		CheckMagics: checkMagics,
		cleanStop:   make(chan struct{}),
	}
	go g.cleanupLoop()
	return g
}

// Stop останавливает фоновую очистку.
func (g *ConnGuard) Stop() {
	close(g.cleanStop)
}

// Allow проверяет, допустимо ли открывать новое соединение от addr.
// Должна вызываться сразу после Accept(), до любых чтений.
func (g *ConnGuard) Allow(addr net.Addr) bool {
	ip := extractIP(addr.String())
	if ip == "" {
		return true
	}

	b := g.bucket(ip)
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-time.Second)

	// Очистить старые записи.
	j := 0
	for _, t := range b.opens {
		if t.After(cutoff) {
			b.opens[j] = t
			j++
		}
	}
	b.opens = b.opens[:j]

	if len(b.opens) >= MaxConnsPerIPPerSec {
		return false
	}
	if b.pending >= MaxPendingPerIP {
		return false
	}

	b.opens = append(b.opens, now)
	b.pending++
	return true
}

// Done сигнализирует, что соединение от addr завершило (или прошло) handshake.
func (g *ConnGuard) Done(addr net.Addr) {
	ip := extractIP(addr.String())
	if ip == "" {
		return
	}
	b := g.bucket(ip)
	b.mu.Lock()
	if b.pending > 0 {
		b.pending--
	}
	b.mu.Unlock()
}

// CheckFirstBytes читает первые MinFirstBytes байт из conn с коротким дедлайном,
// затем проверяет, что они соответствуют одному из KnownMagics.
//
// Возвращает прочитанные байты (должны быть "prepend" обратно в Reader)
// и ошибку, если трафик не распознан.
//
// Если ConnGuard создан с checkMagics=false — всегда возвращает nil ошибку.
func (g *ConnGuard) CheckFirstBytes(conn net.Conn) (peeked []byte, err error) {
	if !g.CheckMagics {
		return nil, nil
	}

	conn.SetReadDeadline(time.Now().Add(FirstBytesDeadline))
	defer conn.SetReadDeadline(time.Time{})

	buf := make([]byte, MinFirstBytes)
	n, readErr := readAtLeast(conn, buf, MinFirstBytes)
	peeked = buf[:n]

	if readErr != nil {
		return peeked, readErr
	}

	if !matchesMagic(peeked) {
		return peeked, ErrUnknownProtocol
	}

	return peeked, nil
}

// ErrUnknownProtocol возвращается, если первые байты не совпадают ни с
// одним известным протоколом.
type ErrUnknownProtocolType struct{}

func (ErrUnknownProtocolType) Error() string {
	return "connguard: unknown protocol in first bytes (possible UDP-in-TCP injection)"
}

var ErrUnknownProtocol = ErrUnknownProtocolType{}

// bucket возвращает (или создаёт) bucket для данного IP.
func (g *ConnGuard) bucket(ip string) *ipBucket {
	g.mu.RLock()
	b, ok := g.buckets[ip]
	g.mu.RUnlock()
	if ok {
		return b
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if b, ok = g.buckets[ip]; ok {
		return b
	}
	b = &ipBucket{}
	g.buckets[ip] = b
	return b
}

func (g *ConnGuard) cleanupLoop() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-g.cleanStop:
			return
		case <-ticker.C:
			g.cleanup()
		}
	}
}

func (g *ConnGuard) cleanup() {
	now := time.Now()
	cutoff := now.Add(-5 * time.Minute)
	g.mu.Lock()
	defer g.mu.Unlock()
	for ip, b := range g.buckets {
		b.mu.Lock()
		// Удаляем неактивные buckets (нет pending и нет свежих opens).
		active := b.pending > 0
		for _, t := range b.opens {
			if t.After(cutoff) {
				active = true
				break
			}
		}
		if !active {
			delete(g.buckets, ip)
		}
		b.mu.Unlock()
	}
}

// matchesMagic возвращает true, если data начинается с одного из KnownMagics.
func matchesMagic(data []byte) bool {
	if len(data) < MinFirstBytes {
		return false
	}
	for _, magic := range KnownMagics {
		if len(magic) > len(data) {
			continue
		}
		match := true
		for i, b := range magic {
			if data[i] != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// readAtLeast читает ровно n байт из r с учётом уже установленного дедлайна.
func readAtLeast(conn net.Conn, buf []byte, n int) (int, error) {
	total := 0
	for total < n {
		nr, err := conn.Read(buf[total:n])
		total += nr
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// Stats возвращает количество отслеживаемых IP.
func (g *ConnGuard) Stats() map[string]interface{} {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return map[string]interface{}{
		"tracked_ips":  len(g.buckets),
		"check_magics": g.CheckMagics,
	}
}
