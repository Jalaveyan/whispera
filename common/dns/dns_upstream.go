package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
)

func (r *Resolver) resolveUpstream(ctx context.Context, domain string) ([]net.IP, error) {
	r.dialCtxMu.RLock()
	dialFn := r.dialCtx
	r.dialCtxMu.RUnlock()

	r.upstreamMu.RLock()
	upstream := r.config.Upstream
	r.upstreamMu.RUnlock()

	if strings.HasPrefix(upstream, "https://") {
		return r.resolveDoH(ctx, upstream, domain)
	}

	if strings.HasPrefix(upstream, "tls://") {
		host := strings.TrimPrefix(upstream, "tls://")
		ips, err := r.resolveDoT(ctx, host, domain)
		if err == nil {
			return ips, nil
		}
		if ips, err2 := r.resolveDoH(ctx, dohFallbackFor(host), domain); err2 == nil {
			return ips, nil
		}
		return nil, err
	}

	if strings.HasPrefix(upstream, "quic://") {
		host := strings.TrimPrefix(upstream, "quic://")
		ips, err := r.resolveDoQ(ctx, host, domain)
		if err == nil {
			return ips, nil
		}
		if ips, err2 := r.resolveDoH(ctx, dohFallbackFor(host), domain); err2 == nil {
			return ips, nil
		}
		return nil, err
	}

	if upstream == "" || strings.EqualFold(upstream, "system") {
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, domain)
		if err != nil {
			return nil, err
		}
		ips := make([]net.IP, len(addrs))
		for i, a := range addrs {
			ips[i] = a.IP
		}
		return ips, nil
	}

	if dialFn != nil {
		ips, err := r.resolveTCPDNS(ctx, dialFn, upstream, domain)
		if err == nil {
			return ips, nil
		}
		if ips, err2 := r.resolveDoH(ctx, dohFallbackFor(upstream), domain); err2 == nil {
			return ips, nil
		}
		return nil, err
	}

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			addr := upstream
			if !strings.Contains(addr, ":") {
				addr += ":53"
			}
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", addr)
		},
	}
	ips, err := resolver.LookupIP(ctx, "ip", domain)
	if err == nil {
		return ips, nil
	}
	return r.resolveDoH(ctx, dohFallbackFor(upstream), domain)
}

func dohFallbackFor(upstream string) string {
	host := strings.TrimSuffix(upstream, ":53")
	host = strings.Split(host, ":")[0]
	switch host {
	case "8.8.8.8", "8.8.4.4", "dns.google":
		return "https://dns.google/dns-query"
	case "9.9.9.9", "149.112.112.112":
		return "https://dns.quad9.net/dns-query"
	case "94.140.14.14", "94.140.15.15":
		return "https://dns.adguard.com/dns-query"
	default:
		return "https://1.1.1.1/dns-query"
	}
}

func (r *Resolver) resolveDoH(ctx context.Context, endpoint, domain string) ([]net.IP, error) {
	r.dialCtxMu.RLock()
	dialFn := r.dialCtx
	r.dialCtxMu.RUnlock()

	var transport http.RoundTripper
	if dialFn != nil {
		transport = &http.Transport{
			DialContext:       dialFn,
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2: true,
		}
	} else {
		transport = &http.Transport{
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2: true,
		}
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}

	query := func(qtype uint16) ([]net.IP, error) {
		msg, qID := buildDNSMsg(domain, qtype)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(msg))
		if err != nil {
			return nil, fmt.Errorf("doh: build request: %w", err)
		}
		req.Header.Set("Content-Type", "application/dns-message")
		req.Header.Set("Accept", "application/dns-message")

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("doh: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("doh: server returned HTTP %d", resp.StatusCode)
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
		if err != nil {
			return nil, fmt.Errorf("doh: read body: %w", err)
		}

		return parseDNSResponse(body, qID)
	}

	return mergeDualStack(query)
}

func (r *Resolver) resolveTCPDNS(ctx context.Context, dialFn func(context.Context, string, string) (net.Conn, error), upstream, domain string) ([]net.IP, error) {
	addr := upstream
	if !strings.Contains(addr, ":") {
		addr += ":53"
	}
	conn, err := dialFn(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("tcp dns dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	query := func(qtype uint16) ([]net.IP, error) {
		msg, qID := buildDNSMsg(domain, qtype)
		lenBuf := [2]byte{byte(len(msg) >> 8), byte(len(msg))}
		conn.Write(lenBuf[:])
		conn.Write(msg)

		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return nil, fmt.Errorf("tcp dns read len: %w", err)
		}
		respLen := int(lenBuf[0])<<8 | int(lenBuf[1])
		if respLen < 12 || respLen > 65535 {
			return nil, fmt.Errorf("tcp dns: invalid response length %d", respLen)
		}
		resp := make([]byte, respLen)
		if _, err := io.ReadFull(conn, resp); err != nil {
			return nil, fmt.Errorf("tcp dns read body: %w", err)
		}
		return parseDNSResponse(resp, qID)
	}

	return mergeDualStack(query)
}

func splitHostPortDefault(upstream, defaultPort string) (host, addr string) {
	if h, _, err := net.SplitHostPort(upstream); err == nil {
		return h, upstream
	}
	return upstream, upstream + ":" + defaultPort
}

func (r *Resolver) resolveDoT(ctx context.Context, upstream, domain string) ([]net.IP, error) {
	r.dialCtxMu.RLock()
	dialFn := r.dialCtx
	r.dialCtxMu.RUnlock()

	host, addr := splitHostPortDefault(upstream, "853")

	var rawConn net.Conn
	var err error
	if dialFn != nil {
		rawConn, err = dialFn(ctx, "tcp", addr)
	} else {
		d := net.Dialer{Timeout: 5 * time.Second}
		rawConn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("dot: dial %s: %w", addr, err)
	}
	defer rawConn.Close()
	rawConn.SetDeadline(time.Now().Add(5 * time.Second))

	conn := tls.Client(rawConn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("dot: handshake: %w", err)
	}

	query := func(qtype uint16) ([]net.IP, error) {
		msg, qID := buildDNSMsg(domain, qtype)
		lenBuf := [2]byte{byte(len(msg) >> 8), byte(len(msg))}
		if _, err := conn.Write(lenBuf[:]); err != nil {
			return nil, fmt.Errorf("dot: write len: %w", err)
		}
		if _, err := conn.Write(msg); err != nil {
			return nil, fmt.Errorf("dot: write msg: %w", err)
		}

		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return nil, fmt.Errorf("dot: read len: %w", err)
		}
		respLen := int(lenBuf[0])<<8 | int(lenBuf[1])
		if respLen < 12 || respLen > 65535 {
			return nil, fmt.Errorf("dot: invalid response length %d", respLen)
		}
		resp := make([]byte, respLen)
		if _, err := io.ReadFull(conn, resp); err != nil {
			return nil, fmt.Errorf("dot: read body: %w", err)
		}
		return parseDNSResponse(resp, qID)
	}

	return mergeDualStack(query)
}

func (r *Resolver) resolveDoQ(ctx context.Context, upstream, domain string) ([]net.IP, error) {
	host, addr := splitHostPortDefault(upstream, "853")

	tlsConf := &tls.Config{
		ServerName: host,
		NextProtos: []string{"doq"},
		MinVersion: tls.VersionTLS13,
	}

	qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	conn, err := quic.DialAddr(qctx, addr, tlsConf, nil)
	if err != nil {
		return nil, fmt.Errorf("doq: dial %s: %w", addr, err)
	}
	defer conn.CloseWithError(0, "")

	doqID := [2]byte{0, 0}
	query := func(qtype uint16) ([]net.IP, error) {
		stream, err := conn.OpenStreamSync(qctx)
		if err != nil {
			return nil, fmt.Errorf("doq: open stream: %w", err)
		}
		defer stream.Close()

		msg, _ := buildDNSMsg(domain, qtype)
		// RFC 9250 §4.2.1: the DNS message ID MUST be 0 over DoQ since the
		// QUIC stream itself provides query/response correlation.
		msg[0], msg[1] = 0, 0

		lenBuf := [2]byte{byte(len(msg) >> 8), byte(len(msg))}
		if _, err := stream.Write(lenBuf[:]); err != nil {
			return nil, fmt.Errorf("doq: write len: %w", err)
		}
		if _, err := stream.Write(msg); err != nil {
			return nil, fmt.Errorf("doq: write msg: %w", err)
		}
		stream.Close()

		if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
			return nil, fmt.Errorf("doq: read len: %w", err)
		}
		respLen := int(lenBuf[0])<<8 | int(lenBuf[1])
		if respLen < 12 || respLen > 65535 {
			return nil, fmt.Errorf("doq: invalid response length %d", respLen)
		}
		resp := make([]byte, respLen)
		if _, err := io.ReadFull(stream, resp); err != nil {
			return nil, fmt.Errorf("doq: read body: %w", err)
		}
		return parseDNSResponse(resp, doqID)
	}

	return mergeDualStack(query)
}
