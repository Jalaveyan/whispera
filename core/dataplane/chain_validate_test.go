package dataplane

import (
	"testing"
	"whispera/core/config"
)

func TestValidateChainGraphCycle(t *testing.T) {
	cs := []config.OutboundConfig{
		{Tag: "a", Chain: []string{"b"}},
		{Tag: "b", Chain: []string{"a"}},
	}
	if err := validateChainGraph(cs); err == nil {
		t.Fatal("expected cycle error")
	}
}

func TestValidateChainGraphLinear(t *testing.T) {
	cs := []config.OutboundConfig{
		{Tag: "exit", Chain: []string{"mid"}},
		{Tag: "mid", Chain: []string{}},
	}
	if err := validateChainGraph(cs); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
}
