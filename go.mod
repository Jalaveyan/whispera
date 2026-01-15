module whispera

go 1.24.1

require (
	github.com/pion/stun v0.6.1
	github.com/quic-go/quic-go v0.58.0
	github.com/refraction-networking/utls v1.8.1
	github.com/xtaci/smux v1.5.50
	golang.org/x/crypto v0.43.0
	golang.org/x/net v0.47.0
	google.golang.org/grpc v1.75.1
	gopkg.in/yaml.v3 v3.0.1
	nhooyr.io/websocket v1.8.10
)

replace (
	golang.org/x/crypto => golang.org/x/crypto v0.41.0
	golang.org/x/net => golang.org/x/net v0.43.0
	golang.org/x/sys => golang.org/x/sys v0.35.0
	golang.org/x/text => golang.org/x/text v0.28.0
	gvisor.dev/gvisor => ./internal/gvisor/gvisor@v0.0.0-20251115042331-9fc4303aefe1
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/kr/text v0.1.0 // indirect
	github.com/pion/dtls/v2 v2.2.7 // indirect
	github.com/pion/logging v0.2.2 // indirect
	github.com/pion/transport/v2 v2.2.1 // indirect
	golang.org/x/sys v0.37.0 // indirect
	golang.org/x/text v0.31.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250818200422-3122310a409c // indirect
	google.golang.org/protobuf v1.36.8 // indirect
)
