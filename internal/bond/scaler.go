package bond

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

type ScalerOpts struct {
	MinMembers    int
	MaxMembers    int
	AvgHighPct    int
	PeakHighPct   int
	HotTicks      int
	Interval      time.Duration
	GrowCooldown  time.Duration
	GrowBatch     int
	DialTimeout   time.Duration
	StallTicks    int
	StallCooldown time.Duration
	Logf          func(format string, args ...interface{})
}

func (o *ScalerOpts) normalize() {
	if o.MinMembers < 1 {
		o.MinMembers = 1
	}
	if o.MaxMembers < o.MinMembers {
		o.MaxMembers = o.MinMembers
	}
	if o.AvgHighPct <= 0 {
		o.AvgHighPct = 60
	}
	if o.PeakHighPct <= 0 {
		o.PeakHighPct = 85
	}
	if o.HotTicks < 1 {
		o.HotTicks = 2
	}
	if o.Interval <= 0 {
		o.Interval = 250 * time.Millisecond
	}
	if o.GrowCooldown <= 0 {
		o.GrowCooldown = 1500 * time.Millisecond
	}
	if o.GrowBatch < 1 {
		o.GrowBatch = 1
	}
	if o.DialTimeout <= 0 {
		o.DialTimeout = 10 * time.Second
	}
	if o.StallTicks < 1 {
		o.StallTicks = 12
	}
	if o.StallCooldown <= 0 {
		o.StallCooldown = 30 * time.Second
	}
}

func StartScaler(ctx context.Context, c *Conn, dial DialFunc, opts ScalerOpts) (stop func()) {
	opts.normalize()

	stopCh := make(chan struct{})

	var stopOnce sync.Once

	stop = func() { stopOnce.Do(func() { close(stopCh) }) }

	go func() {
		t := time.NewTicker(opts.Interval)
		defer t.Stop()

		var hot int
		var lastGrow time.Time
		var lastFallback uint64
		var growsSincePressure int
		var stallUntil time.Time
		var growing atomic.Int32

		for {
			select {
			case <-stopCh:
				return
			case <-c.closed:
				return
			case <-ctx.Done():
				return
			case <-t.C:
			}

			if growing.Load() != 0 {
				continue
			}
			if !stallUntil.IsZero() && time.Now().Before(stallUntil) {
				continue
			}

			width := c.Width()
			if width >= opts.MaxMembers {
				continue
			}

			avg, peak, low, fbHits := c.QueuePressure()
			fbDelta := fbHits - lastFallback
			lastFallback = fbHits

			pressure := low >= opts.AvgHighPct || fbDelta > 0
			if !pressure {
				hot = 0
				growsSincePressure = 0
				continue
			}

			hot++

			if hot < opts.HotTicks && fbDelta == 0 {
				continue
			}

			if time.Since(lastGrow) < opts.GrowCooldown {
				continue
			}

			batch := opts.GrowBatch
			if width+batch > opts.MaxMembers {
				batch = opts.MaxMembers - width
			}
			if batch < 1 {
				continue
			}

			lastGrow = time.Now()

			hot = 0
			growsSincePressure++
			growing.Store(int32(batch))

			if opts.Logf != nil {
				opts.Logf("bond/scaler: grow %d->%d (min=%d%% avg=%d%% peak=%d%% fbΔ=%d)",
					width, width+batch, low, avg, peak, fbDelta)
			}

			snapshot := growsSincePressure
			for i := 0; i < batch; i++ {
				go func() {
					defer growing.Add(-1)

					gctx, cancel := context.WithTimeout(ctx, opts.DialTimeout)

					defer cancel()

					if err := c.Grow(gctx, dial); err != nil {
						if opts.Logf != nil {
							opts.Logf("bond/scaler: grow failed: %v", err)
						}
					}
				}()
			}

			if snapshot >= opts.StallTicks {
				stallUntil = time.Now().Add(opts.StallCooldown)
				growsSincePressure = 0
				if opts.Logf != nil {
					opts.Logf("bond/scaler: growth not relieving pressure, stalling for %s", opts.StallCooldown)
				}
			}
		}
	}()

	return stop
}
