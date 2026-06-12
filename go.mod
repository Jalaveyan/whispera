module whispera

go 1.26

require (
	github.com/go-telegram-bot-api/telegram-bot-api/v5 v5.5.1
	github.com/google/uuid v1.6.0
	github.com/gopacket/gopacket v1.6.0
	github.com/hashicorp/golang-lru/v2 v2.0.7
	github.com/hashicorp/yamux v0.1.2
	github.com/jackc/pgx/v5 v5.8.0
	github.com/nats-io/nats.go v1.49.0
	github.com/pion/interceptor v0.1.43
	github.com/pion/rtp v1.10.1
	github.com/pion/webrtc/v3 v3.2.24
	github.com/quic-go/quic-go v0.59.0
	github.com/redis/go-redis/v9 v9.17.3
	github.com/refraction-networking/utls v1.8.3-0.20260301010127-aa6edf4b11af
	github.com/sourcegraph/conc v0.3.0
	go.uber.org/automaxprocs v1.6.0
	go.uber.org/zap v1.27.1
	golang.org/x/crypto v0.49.0
	golang.org/x/net v0.52.0
	golang.org/x/sync v0.20.0
	google.golang.org/grpc v1.73.0
	gopkg.in/yaml.v3 v3.0.1
	gorgonia.org/gorgonia v0.9.18
	gorgonia.org/tensor v0.9.24
	nhooyr.io/websocket v1.8.10
)

require (
	github.com/apache/arrow/go/arrow v0.0.0-20211112161151-bc219186db40 // indirect
	github.com/awalterschulze/gographviz v2.0.3+incompatible // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/chewxy/hm v1.0.0 // indirect
	github.com/chewxy/math32 v1.10.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/flatbuffers v2.0.6+incompatible // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/leesper/go_rng v0.0.0-20190531154944-a612b043e353 // indirect
	github.com/nats-io/nkeys v0.4.12 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/pion/datachannel v1.6.0 // indirect
	github.com/pion/ice/v2 v2.3.11 // indirect
	github.com/pion/mdns v0.0.8 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/rtcp v1.2.16 // indirect
	github.com/pion/sctp v1.9.2 // indirect
	github.com/pion/sdp/v3 v3.0.17 // indirect
	github.com/pion/srtp/v2 v2.0.18 // indirect
	github.com/pion/stun v0.6.1 // indirect
	github.com/pion/transport/v4 v4.0.1 // indirect
	github.com/pion/turn/v2 v2.1.3 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	github.com/xtgo/set v1.0.0 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go4.org/unsafe/assume-no-moving-gc v0.0.0-20231121144256-b99613f794b6 // indirect
	golang.org/x/exp v0.0.0-20250911091902-df9299821621 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	gonum.org/v1/gonum v0.16.0 // indirect
	gorgonia.org/cu v0.9.4 // indirect
	gorgonia.org/dawson v1.2.0 // indirect
	gorgonia.org/vecf32 v0.9.0 // indirect
	gorgonia.org/vecf64 v0.9.0 // indirect
)

replace (
	golang.org/x/crypto => golang.org/x/crypto v0.41.0
	golang.org/x/net => golang.org/x/net v0.43.0
	golang.org/x/sys => golang.org/x/sys v0.35.0
	golang.org/x/text => golang.org/x/text v0.28.0
// gvisor.dev/gvisor => ./internal/gvisor/gvisor@v0.0.0-20251115042331-9fc4303aefe1
)

require (
	github.com/andybalholm/brotli v1.1.1 // indirect
	github.com/klauspost/compress v1.18.2 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/klauspost/reedsolomon v1.13.0
	github.com/pion/dtls/v2 v2.2.7 // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/transport/v2 v2.2.3 // indirect
	golang.org/x/sys v0.42.0
	golang.org/x/text v0.35.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)
