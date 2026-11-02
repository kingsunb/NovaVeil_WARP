package warp

import (
	"crypto/rand"
	"encoding/binary"
	"net/netip"
)

// WARP IPv4 入口段, 来源见 README.
var warpIPv4Prefixes = []netip.Prefix{
	netip.MustParsePrefix("8.6.112.0/24"),
	netip.MustParsePrefix("8.34.70.0/24"),
	netip.MustParsePrefix("8.34.146.0/24"),
	netip.MustParsePrefix("8.35.211.0/24"),
	netip.MustParsePrefix("8.39.125.0/24"),
	netip.MustParsePrefix("8.39.204.0/24"),
	netip.MustParsePrefix("8.39.214.0/24"),
	netip.MustParsePrefix("8.47.69.0/24"),
	netip.MustParsePrefix("162.159.192.0/24"),
	netip.MustParsePrefix("162.159.193.0/24"),
	netip.MustParsePrefix("162.159.195.0/24"),
	netip.MustParsePrefix("162.159.204.0/24"),
	netip.MustParsePrefix("188.114.96.0/24"),
	netip.MustParsePrefix("188.114.97.0/24"),
	netip.MustParsePrefix("188.114.98.0/24"),
	netip.MustParsePrefix("188.114.99.0/24"),
}

// 公开 WARP 端口, 2408 为主.
var warpPorts = []uint16{
	500, 854, 859, 864, 878, 880, 890, 891, 894, 903,
	908, 928, 934, 939, 942, 943, 945, 946, 955, 968,
	987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387,
	1701, 1843, 2371, 2408, 2506, 3138, 3476, 3581, 3854, 4177,
	4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281, 7559,
	8319, 8742, 8854, 8886,
}

type endpointConfig struct {
	ipv4Pool    bool
	ipv4Samples int
	extra       []string
}

// candidates 按栈组装入口, v4 才前置随机入口.
func (c endpointConfig) candidates(reg registration, stack Stack) []string {
	out := make([]string, 0, len(c.extra)+c.ipv4Samples+len(reg.Endpoints))
	out = append(out, c.extra...)
	if stack == StackIPv4 && c.ipv4Pool {
		out = append(out, randomIPv4Endpoints(c.ipv4Samples)...)
	}
	// 注册结果已含兜底入口, 不再重复.
	out = append(out, reg.Endpoints...)
	return out
}

// randomIPv4Endpoints 去重抽取随机入口.
func randomIPv4Endpoints(count int) []string {
	if count <= 0 {
		return nil
	}
	out := make([]string, 0, count)
	seen := make(map[string]struct{}, count)
	for attempts := 0; len(out) < count && attempts < count*8; attempts++ {
		endpoint := randomIPv4Endpoint()
		if _, ok := seen[endpoint]; ok {
			continue
		}
		seen[endpoint] = struct{}{}
		out = append(out, endpoint)
	}
	return out
}

func randomIPv4Endpoint() string {
	prefix := warpIPv4Prefixes[randomIndex(len(warpIPv4Prefixes))]
	address := prefix.Masked().Addr().As4()
	address[3] = byte(1 + randomIndex(254))
	port := warpPorts[randomIndex(len(warpPorts))]
	if randomIndex(4) != 0 {
		port = 2408
	}
	return netip.AddrPortFrom(netip.AddrFrom4(address), port).String()
}

func randomIndex(limit int) int {
	if limit <= 1 {
		return 0
	}
	var buffer [8]byte
	if _, err := rand.Read(buffer[:]); err != nil {
		return 0
	}
	return int(binary.BigEndian.Uint64(buffer[:]) % uint64(limit))
}
