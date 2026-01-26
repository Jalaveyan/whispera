package proxy

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// HTTPProxy реализует HTTP прокси сервер
type HTTPProxy struct {
	config      *Config
	server      *http.Server
	authHandler AuthHandler
	stats       *Stats
	listener    net.Listener
}

// NewHTTPProxy создает новый HTTP прокси
func NewHTTPProxy(config *Config) *HTTPProxy {
	return &HTTPProxy{
		config: config,
		stats: &Stats{
			StartTime: time.Now(),
		},
	}
}

// SetAuthHandler устанавливает обработчик аутентификации
func (p *HTTPProxy) SetAuthHandler(handler AuthHandler) {
	p.authHandler = handler
}

// Type возвращает тип прокси
func (p *HTTPProxy) Type() ProxyType {
	return ProxyHTTP
}

// Start запускает HTTP прокси сервер
func (p *HTTPProxy) Start(ctx context.Context) error {
	listener, err := net.Listen("tcp", p.config.Addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", p.config.Addr, err)
	}
	p.listener = listener

	p.server = &http.Server{
		Addr:         p.config.Addr,
		Handler:      http.HandlerFunc(p.handleRequest),
		ReadTimeout:  p.config.Timeout,
		WriteTimeout: p.config.Timeout,
		IdleTimeout:  p.config.IdleTimeout,
	}

	log.Printf("[HTTP-PROXY] ✅ Server listening on %s", p.config.Addr)

	// Запускаем сервер в горутине
	go func() {
		if err := p.server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("[HTTP-PROXY] ❌ Server error: %v", err)
		}
	}()

	// Ожидаем контекст для остановки
	<-ctx.Done()
	return p.Stop()
}

// Stop останавливает HTTP прокси сервер
func (p *HTTPProxy) Stop() error {
	if p.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return p.server.Shutdown(ctx)
	}
	return nil
}

// Addr возвращает адрес прослушивания
func (p *HTTPProxy) Addr() net.Addr {
	if p.listener != nil {
		return p.listener.Addr()
	}
	return nil
}

// Stats возвращает статистику
func (p *HTTPProxy) Stats() *Stats {
	return p.stats
}

// Reset сбрасывает статистику
func (p *HTTPProxy) Reset() {
	p.stats = &Stats{
		StartTime: time.Now(),
	}
}

// handleRequest обрабатывает HTTP запрос
func (p *HTTPProxy) handleRequest(w http.ResponseWriter, r *http.Request) {
	p.stats.Connections++

	// Проверка аутентификации
	if p.authHandler != nil && !p.checkAuth(r) {
		p.stats.Errors++
		p.sendAuthRequired(w)
		return
	}

	switch r.Method {
	case http.MethodConnect:
		p.handleHTTPS(w, r)
	default:
		p.handleHTTP(w, r)
	}
}

// checkAuth проверяет аутентификацию
func (p *HTTPProxy) checkAuth(r *http.Request) bool {
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		return false
	}

	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || parts[0] != "Basic" {
		return false
	}

	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}

	credentials := strings.SplitN(string(decoded), ":", 2)
	if len(credentials) != 2 {
		return false
	}

	return p.authHandler.Authenticate(credentials[0], credentials[1])
}

// sendAuthRequired отправляет требование аутентификации
func (p *HTTPProxy) sendAuthRequired(w http.ResponseWriter) {
	w.Header().Set("Proxy-Authenticate", "Basic realm=\"Whispera Proxy\"")
	w.WriteHeader(http.StatusProxyAuthRequired)
}

// handleHTTPS обрабатывает HTTPS CONNECT запрос
func (p *HTTPProxy) handleHTTPS(w http.ResponseWriter, r *http.Request) {
	// Устанавливаем соединение с целевым сервером
	dstConn, err := net.DialTimeout("tcp", r.Host, p.config.Timeout)
	if err != nil {
		p.stats.Errors++
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer dstConn.Close()

	// Отправляем 200 OK клиенту
	w.WriteHeader(http.StatusOK)

	// Получаем соединение с клиентом
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		p.stats.Errors++
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		p.stats.Errors++
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	// Начинаем проксирование данных
	p.proxyData(clientConn, dstConn)
}

// handleHTTP обрабатывает обычный HTTP запрос
func (p *HTTPProxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Модифицируем запрос для проксирования
	r.RequestURI = ""
	r.URL.Host = r.Host
	r.URL.Scheme = "http"

	// Создаем транспорт для отправки запроса
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.DialTimeout(network, addr, p.config.Timeout)
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   p.config.Timeout,
	}

	// Отправляем запрос
	resp, err := client.Do(r)
	if err != nil {
		p.stats.Errors++
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	// Копируем заголовки ответа
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(resp.StatusCode)

	// Копируем тело ответа
	io.Copy(w, resp.Body)
}

// proxyData проксирует данные между соединениями с оптимизацией для zero-copy
func (p *HTTPProxy) proxyData(client, server net.Conn) {
	done := make(chan struct{}, 2)
	
	// Пул буферов для переиспользования (256KB для оптимальной пропускной способности)
	bufSize := 256 * 1024

	// Client -> Server
	go func() {
		defer client.Close()
		defer server.Close()
		// io.CopyBuffer использует предоставленный буфер (избегаем аллокации)
		buf := make([]byte, bufSize)
		io.CopyBuffer(server, client, buf)
		done <- struct{}{}
	}()

	// Server -> Client
	go func() {
		defer client.Close()
		defer server.Close()
		buf := make([]byte, bufSize)
		io.CopyBuffer(client, server, buf)
		done <- struct{}{}
	}()

	// Ждем завершения любой из горутин
	<-done
}
