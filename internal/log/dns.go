package logger

import "time"

type DNSEvent struct {
	Domain  string
	Qtype   string
	Answer  string
	Latency time.Duration
	Client  string
}

var dnsLog = Module("dns")

func DNS() *Logger { return dnsLog }

func LogDNS(ev DNSEvent) {
	dnsLog.s.Infow("query",
		"domain", ev.Domain,
		"type", ev.Qtype,
		"answer", ev.Answer,
		"ms", ev.Latency.Milliseconds(),
		"client", ev.Client,
	)
}
