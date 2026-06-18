package config

type RelayConfig struct {
	MaxStreams    int    `yaml:"max_streams"`
	EnableTCP     bool   `yaml:"enable_tcp"`
	EnableUDP     bool   `yaml:"enable_udp"`
	Debug         bool   `yaml:"debug"`
	UpstreamProxy string `yaml:"upstream_proxy"`
}
