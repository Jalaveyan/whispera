module whispera

go 1.25.6

require (
	github.com/go-telegram-bot-api/telegram-bot-api/v5 v5.5.1
	github.com/google/uuid v1.6.0
	github.com/hashicorp/yamux v0.1.2
	github.com/jackc/pgx/v5 v5.8.0
	github.com/pion/stun v0.6.1
	github.com/pion/webrtc/v3 v3.2.24
	github.com/quic-go/quic-go v0.59.0
	github.com/redis/go-redis/v9 v9.17.3
	github.com/refraction-networking/utls v1.8.1
	golang.org/x/crypto v0.47.0
	golang.org/x/net v0.47.0
	google.golang.org/grpc v1.75.1
	gopkg.in/yaml.v3 v3.0.1
	nhooyr.io/websocket v1.8.10
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/nats-io/nats.go v1.49.0 // indirect
	github.com/nats-io/nkeys v0.4.12 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/pion/datachannel v1.5.5 // indirect
	github.com/pion/ice/v2 v2.3.11 // indirect
	github.com/pion/interceptor v0.1.25 // indirect
	github.com/pion/mdns v0.0.8 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/rtcp v1.2.12 // indirect
	github.com/pion/rtp v1.8.3 // indirect
	github.com/pion/sctp v1.8.8 // indirect
	github.com/pion/sdp/v3 v3.0.6 // indirect
	github.com/pion/srtp/v2 v2.0.18 // indirect
	github.com/pion/turn/v2 v2.1.3 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	golang.org/x/sync v0.17.0 // indirect
)

replace (
	golang.org/x/crypto => golang.org/x/crypto v0.41.0
	golang.org/x/net => golang.org/x/net v0.43.0
	golang.org/x/sys => golang.org/x/sys v0.35.0
	golang.org/x/text => golang.org/x/text v0.28.0
// gvisor.dev/gvisor => ./internal/gvisor/gvisor@v0.0.0-20251115042331-9fc4303aefe1
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/klauspost/compress v1.18.2 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/klauspost/reedsolomon v1.13.0
	github.com/pion/dtls/v2 v2.2.7 // indirect
	github.com/pion/logging v0.2.2 // indirect
	github.com/pion/transport/v2 v2.2.3 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/text v0.31.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250818200422-3122310a409c // indirect
	google.golang.org/protobuf v1.36.8 // indirect
)
