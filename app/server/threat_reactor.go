package main

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"sync/atomic"
	"time"

	"whispera/core/config"
	"whispera/neural/evasion"
)

func envInt(name string, fallback int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func envString(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

type threatReactor struct {
	sc            *config.ServerConfig
	boostLevel    int
	boostDuration time.Duration
	decoyCooldown time.Duration
	decoyScript   string

	boostUntil   atomic.Int64
	lastDecoyRun atomic.Int64
	adversarial  atomic.Pointer[evasion.AdversarialEngine]
}

func newThreatReactor(sc *config.ServerConfig) *threatReactor {
	return &threatReactor{
		sc:            sc,
		boostLevel:    envInt("WHISPERA_THREAT_BOOST_LEVEL", 10),
		boostDuration: time.Duration(envInt("WHISPERA_THREAT_BOOST_DURATION_SEC", 600)) * time.Second,
		decoyCooldown: time.Duration(envInt("WHISPERA_DECOY_REFRESH_COOLDOWN_SEC", 300)) * time.Second,
		decoyScript:   envString("WHISPERA_DECOY_REFRESH_SCRIPT", "/usr/local/bin/whispera-refresh-decoy.sh"),
	}
}

func (r *threatReactor) SetAdversarial(ae *evasion.AdversarialEngine) {
	r.adversarial.Store(ae)
}

func (r *threatReactor) EffectiveThreatLevel() int {
	base := r.sc.Obfuscation.ThreatLevel
	if time.Now().UnixNano() < r.boostUntil.Load() && r.boostLevel > base {
		return r.boostLevel
	}
	return base
}

func (r *threatReactor) OnTSPUDetected(dpiType int, confidence float64) {
	r.boostUntil.Store(time.Now().Add(r.boostDuration).UnixNano())

	if ae := r.adversarial.Load(); ae != nil {
		strategy, intensity := ae.CurrentStrategy()
		ae.RecordFeedback(true, strategy, intensity, evasion.ZeroFeatures())
	}

	now := time.Now().UnixNano()
	last := r.lastDecoyRun.Load()
	if now-last <= r.decoyCooldown.Nanoseconds() {
		return
	}
	if !r.lastDecoyRun.CompareAndSwap(last, now) {
		return
	}
	if _, err := os.Stat(r.decoyScript); err != nil {
		return
	}
	go func() { _ = exec.CommandContext(context.Background(), r.decoyScript).Run() }()
}
