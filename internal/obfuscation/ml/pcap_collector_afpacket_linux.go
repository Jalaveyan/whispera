//go:build linux

package ml

import (
	"fmt"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/afpacket"
	"github.com/gopacket/gopacket/layers"
)

type PCAPCollector struct {
	iface  string
	port   int
	out    chan LabeledFlow
	stopCh chan struct{}
}

func NewPCAPCollector(iface string, port int) *PCAPCollector {
	return &PCAPCollector{
		iface:  iface,
		port:   port,
		out:    make(chan LabeledFlow, 256),
		stopCh: make(chan struct{}),
	}
}

func (c *PCAPCollector) Out() <-chan LabeledFlow { return c.out }
func (c *PCAPCollector) Stop()                   { close(c.stopCh) }

func (c *PCAPCollector) Start() error {
	tp, err := afpacket.NewTPacket(
		afpacket.OptInterface(c.iface),
		afpacket.OptFrameSize(4096),
		afpacket.OptBlockSize(1<<20),
		afpacket.OptNumBlocks(16),
		afpacket.OptPollTimeout(time.Second),
	)
	if err != nil {
		return fmt.Errorf("afpacket: open %s: %w", c.iface, err)
	}

	go func() {
		<-c.stopCh
		tp.Close()
	}()

	go c.capture(tp)
	return nil
}

func (c *PCAPCollector) capture(tp *afpacket.TPacket) {
	src := gopacket.NewPacketSource(tp, layers.LayerTypeEthernet)
	src.NoCopy = true
	src.Lazy = true

	agg := newFlowAggregator(c.port, c.out)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for packet := range src.Packets() {
		meta := packet.Metadata()
		ts := float64(meta.Timestamp.UnixNano()) / 1e9
		size := meta.Length
		if size == 0 {
			size = meta.CaptureLength
		}

		var srcIP, dstIP string
		if ip4 := packet.Layer(layers.LayerTypeIPv4); ip4 != nil {
			l := ip4.(*layers.IPv4)
			srcIP = l.SrcIP.String()
			dstIP = l.DstIP.String()
		} else if ip6 := packet.Layer(layers.LayerTypeIPv6); ip6 != nil {
			l := ip6.(*layers.IPv6)
			srcIP = l.SrcIP.String()
			dstIP = l.DstIP.String()
		} else {
			continue
		}

		tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		if !ok {
			continue
		}

		agg.observe(ts, srcIP, dstIP, int(tcp.SrcPort), int(tcp.DstPort), size)

		select {
		case <-ticker.C:
			agg.sweep(ts)
		default:
		}
	}
}
