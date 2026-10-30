package warp

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	probeTimeout    = 5 * time.Second
	probeCandidates = 10
)

type Stack string

const (
	StackIPv4 Stack = "ipv4"
	StackIPv6 Stack = "ipv6"
	StackDual Stack = "dual"

	// DefaultStack is IPv6: a WARP IPv4 egress is a public address shared by
	// every user behind Cloudflare's NAT, so the upstream's per-address free
	// quota is usually already spent, while the IPv6 egress belongs to the
	// tunnel. The handshake still falls back to IPv4 endpoints when IPv6 does
	// not answer, so an IPv4-only host keeps working without extra settings.
	DefaultStack = StackIPv6
)

var (
	dnsV4 = netip.MustParseAddr("1.1.1.1")
	dnsV6 = netip.MustParseAddr("2606:4700:4700::1111")
)

func ParseStack(value string) (Stack, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return DefaultStack, nil
	case "ipv6", "v6":
		return StackIPv6, nil
	case "ipv4", "v4":
		return StackIPv4, nil
	case "dual", "both":
		return StackDual, nil
	default:
		return "", fmt.Errorf("unsupported WARP stack %q; use ipv6, ipv4 or dual", value)
	}
}

type exit struct {
	id        string
	egress    netip.Addr
	stack     Stack
	reg       registration
	source    netip.Addr
	device    *device.Device
	network   *netstack.Net
	verify    func(context.Context) (netip.Addr, error)
	mu        sync.Mutex
	refs      int
	pins      int
	retired   bool
	closed    bool
	penalized bool
	closeOnce sync.Once
	connMu    sync.Mutex
	conns     map[*exitConn]struct{}
	connsDone bool
}

// exitConn tracks one dialed connection so a penalized exit can close its
// existing tunnels immediately. Without this, a client that keeps a CONNECT
// tunnel alive would keep retrying through the exhausted egress.
type exitConn struct {
	net.Conn
	exit *exit
	once sync.Once
}

func (c *exitConn) Close() error {
	var err error
	c.once.Do(func() {
		c.exit.connMu.Lock()
		delete(c.exit.conns, c)
		c.exit.connMu.Unlock()
		err = c.Conn.Close()
	})
	return err
}

func (c *exitConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func newExit(ctx context.Context, reg registration) (*exit, error) {
	return newExitWithStack(ctx, reg, DefaultStack, netip.Addr{})
}

// newExitWithStack builds one userspace tunnel for reg. A valid source pins
// the outer WireGuard socket to that address and restricts the peer endpoints
// to IPv6, so the public egress is derived from the rotating source rather than
// from whatever address the host happens to share.
func newExitWithStack(ctx context.Context, reg registration, stack Stack, source netip.Addr) (*exit, error) {
	normalized, err := ParseStack(string(stack))
	if err != nil {
		return nil, err
	}
	stack = normalized
	localV6, v6Err := parseAddress(reg.AddressV6)
	localV4, v4Err := parseAddress(reg.AddressV4)
	var localAddresses []netip.Addr
	var dns []netip.Addr
	switch stack {
	case StackIPv6:
		if v6Err != nil || !localV6.Is6() {
			return nil, fmt.Errorf("invalid WARP IPv6 address %q", reg.AddressV6)
		}
		localAddresses = []netip.Addr{localV6}
		dns = []netip.Addr{dnsV6}
	case StackIPv4:
		if v4Err != nil || !localV4.Is4() {
			return nil, fmt.Errorf("invalid WARP IPv4 address %q", reg.AddressV4)
		}
		localAddresses = []netip.Addr{localV4}
		dns = []netip.Addr{dnsV4}
	case StackDual:
		if v6Err == nil && localV6.Is6() {
			localAddresses = append(localAddresses, localV6)
		}
		if v4Err == nil && localV4.Is4() {
			localAddresses = append(localAddresses, localV4)
		}
		if len(localAddresses) == 0 {
			return nil, fmt.Errorf("WARP registration has no usable address: v4=%q v6=%q", reg.AddressV4, reg.AddressV6)
		}
		dns = []netip.Addr{dnsV4, dnsV6}
	}
	tunDevice, network, err := netstack.CreateNetTUN(localAddresses, dns, 1280)
	if err != nil {
		return nil, fmt.Errorf("create WARP network stack: %w", err)
	}
	privateKey, err := uapiKey(reg.PrivateKey)
	if err != nil {
		tunDevice.Close()
		return nil, fmt.Errorf("decode WARP private key: %w", err)
	}
	peerKey, err := uapiKey(reg.PeerPublicKey)
	if err != nil {
		tunDevice.Close()
		return nil, fmt.Errorf("decode WARP peer key: %w", err)
	}
	endpoints, err := resolveEndpoints(ctx, reg.Endpoints, reg.Endpoint)
	if err != nil {
		tunDevice.Close()
		return nil, err
	}
	if source.IsValid() {
		// Try IPv6 endpoints first so the rotating source is used, but keep
		// the IPv4 ones behind them: a host (or network) that cannot reach
		// Cloudflare over IPv6 still gets a working tunnel, just with the
		// shared address the prefix was supposed to avoid.
		endpoints = preferIPv6Endpoints(endpoints)
	}
	wg := device.NewDevice(tunDevice, &simpleBind{source: source}, device.NewLogger(device.LogLevelError, "warp: "))
	uapi := fmt.Sprintf(
		"private_key=%s\npublic_key=%s\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\nendpoint=%s\npersistent_keepalive_interval=25\n",
		privateKey, peerKey, endpoints[0],
	)
	if err := wg.IpcSet(uapi); err != nil {
		wg.Close()
		<-wg.Wait()
		return nil, fmt.Errorf("configure WARP device: %w", err)
	}
	if err := wg.Up(); err != nil {
		wg.Close()
		<-wg.Wait()
		return nil, fmt.Errorf("start WARP device: %w", err)
	}
	e := &exit{id: reg.ID, stack: stack, device: wg, network: network, reg: reg, source: source}
	egress, err := e.probe(ctx, wg, peerKey, endpoints)
	if err != nil {
		e.close()
		return nil, err
	}
	e.egress = egress
	e.verify = func(ctx context.Context) (netip.Addr, error) {
		return e.probe(ctx, wg, peerKey, endpoints)
	}
	return e, nil
}

// verifyEgress 重探该出口的公网地址, 供周期巡检使用.
func (e *exit) verifyEgress(ctx context.Context) (netip.Addr, error) {
	e.mu.Lock()
	verify := e.verify
	retired := e.retired || e.closed
	e.mu.Unlock()
	if retired {
		return netip.Addr{}, errors.New("WARP exit is retired")
	}
	if verify == nil {
		return netip.Addr{}, errors.New("WARP exit has no verifier")
	}
	return verify(ctx)
}

// preferIPv6Endpoints returns endpoints with the IPv6 ones first and the IPv4
// ones after them, both in their original order. Nothing is dropped: an IPv4
// fallback keeps WARP usable on a host that cannot reach Cloudflare over IPv6.
func preferIPv6Endpoints(endpoints []string) []string {
	ordered := make([]string, 0, len(endpoints))
	ipv4 := make([]string, 0, len(endpoints))
	for _, endpoint := range endpoints {
		host, _, err := net.SplitHostPort(endpoint)
		if err != nil {
			continue
		}
		addr, err := netip.ParseAddr(host)
		if err != nil || addr.Is4In6() {
			continue
		}
		if addr.Is6() {
			ordered = append(ordered, endpoint)
		} else {
			ipv4 = append(ipv4, endpoint)
		}
	}
	return append(ordered, ipv4...)
}

func resolveEndpoints(ctx context.Context, candidates []string, fallback string) ([]string, error) {
	if len(candidates) == 0 && fallback != "" {
		candidates = []string{fallback}
	}
	seen := make(map[string]bool)
	var endpoints []string
	for _, candidate := range candidates {
		normalized, err := normalizeEndpoint(candidate)
		if err != nil {
			continue
		}
		host, port, _ := net.SplitHostPort(normalized)
		if net.ParseIP(host) != nil {
			if !seen[normalized] {
				seen[normalized] = true
				endpoints = append(endpoints, normalized)
			}
		} else {
			addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				continue
			}
			for _, ip := range addrs {
				value := net.JoinHostPort(ip.IP.String(), port)
				if !seen[value] {
					seen[value] = true
					endpoints = append(endpoints, value)
				}
			}
		}
		if len(endpoints) >= probeCandidates {
			break
		}
	}
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("resolve WARP endpoint candidates %v", candidates)
	}
	return endpoints[:min(len(endpoints), probeCandidates)], nil
}

func normalizeEndpoint(endpoint string) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	if !strings.Contains(endpoint, ":") {
		endpoint = net.JoinHostPort(endpoint, "2408")
	} else if addr, err := netip.ParseAddr(endpoint); err == nil {
		endpoint = net.JoinHostPort(addr.String(), "2408")
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return "", fmt.Errorf("invalid WARP endpoint %q", endpoint)
	}
	if port == "" || port == "0" {
		port = "2408"
	}
	return net.JoinHostPort(host, port), nil
}

func parseAddress(value string) (netip.Addr, error) {
	value = strings.TrimSpace(value)
	if addr, err := netip.ParseAddr(value); err == nil {
		return addr.Unmap(), nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Addr{}, err
	}
	return prefix.Addr().Unmap(), nil
}

func uapiKey(encoded string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil || len(key) != 32 {
		return "", errors.New("invalid WireGuard key")
	}
	return hex.EncodeToString(key), nil
}

type probeTarget struct {
	network string
	url     string
}

func probeTargets(stack Stack) []probeTarget {
	switch stack {
	case StackIPv4:
		return []probeTarget{{network: "tcp4", url: "https://1.1.1.1/cdn-cgi/trace"}}
	case StackDual:
		return []probeTarget{
			{network: "tcp4", url: "https://1.1.1.1/cdn-cgi/trace"},
			{network: "tcp6", url: "https://[2606:4700:4700::1111]/cdn-cgi/trace"},
		}
	default:
		return []probeTarget{{network: "tcp6", url: "https://[2606:4700:4700::1111]/cdn-cgi/trace"}}
	}
}

func (e *exit) probe(ctx context.Context, wg *device.Device, peerKey string, endpoints []string) (netip.Addr, error) {
	var lastErr error
	for index, endpoint := range endpoints {
		if index > 0 {
			if err := wg.IpcSet(fmt.Sprintf("public_key=%s\nendpoint=%s\n", peerKey, endpoint)); err != nil {
				lastErr = fmt.Errorf("switch WARP endpoint to %s: %w", endpoint, err)
				continue
			}
		}
		for _, target := range probeTargets(e.stack) {
			egress, err := e.probeTarget(ctx, target)
			if err == nil {
				return egress, nil
			}
			lastErr = err
		}
	}
	return netip.Addr{}, fmt.Errorf("verify WARP %s egress: %w", e.stack, lastErr)
}

func (e *exit) probeTarget(ctx context.Context, target probeTarget) (netip.Addr, error) {
	probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	transport := &http.Transport{
		Proxy:               nil,
		ForceAttemptHTTP2:   false,
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 10 * time.Second,
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			return e.network.DialContext(ctx, target.network, address)
		},
	}
	defer transport.CloseIdleConnections()
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, target.url, nil)
	if err != nil {
		return netip.Addr{}, err
	}
	resp, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		return netip.Addr{}, err
	}
	defer resp.Body.Close()
	egress, err := parseTrace(resp.Body)
	if err != nil {
		return netip.Addr{}, err
	}
	if target.network == "tcp4" && !egress.Is4() {
		return netip.Addr{}, fmt.Errorf("WARP trace over IPv4 reported %s", egress)
	}
	if target.network == "tcp6" && !egress.Is6() {
		return netip.Addr{}, fmt.Errorf("WARP trace over IPv6 reported %s", egress)
	}
	return egress, nil
}

func parseTrace(body io.Reader) (netip.Addr, error) {
	scanner := bufio.NewScanner(io.LimitReader(body, 64<<10))
	var rawIP string
	warpEnabled := false
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "ip":
			rawIP = strings.TrimSpace(value)
		case "warp":
			warpEnabled = strings.TrimSpace(value) == "on"
		}
	}
	if err := scanner.Err(); err != nil {
		return netip.Addr{}, err
	}
	if !warpEnabled {
		return netip.Addr{}, errors.New("Cloudflare trace reports warp=off")
	}
	addr, err := netip.ParseAddr(rawIP)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid trace IP %q", rawIP)
	}
	addr = addr.Unmap()
	if (!addr.Is4() && !addr.Is6()) || !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return netip.Addr{}, fmt.Errorf("trace returned non-public address %s", addr)
	}
	return addr, nil
}

func (e *exit) addRef() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.retired || e.closed {
		return false
	}
	e.refs++
	return true
}

func (e *exit) addPin() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.retired || e.closed {
		return false
	}
	e.pins++
	return true
}

func (e *exit) release() {
	e.releaseReference(false)
}

func (e *exit) releasePin() {
	e.releaseReference(true)
}

func (e *exit) releaseReference(pin bool) {
	e.mu.Lock()
	if pin {
		if e.pins > 0 {
			e.pins--
		}
	} else if e.refs > 0 {
		e.refs--
	}
	closeNow := e.closeReadyLocked()
	e.mu.Unlock()
	if closeNow {
		e.close()
	}
}

func (e *exit) closeReadyLocked() bool {
	return e.refs == 0 && e.pins == 0 && e.retired && !e.closed
}

func (e *exit) trackConn(c *exitConn) bool {
	e.connMu.Lock()
	defer e.connMu.Unlock()
	if e.connsDone {
		return false
	}
	if e.conns == nil {
		e.conns = make(map[*exitConn]struct{})
	}
	e.conns[c] = struct{}{}
	return true
}

func (e *exit) closeConns() {
	e.connMu.Lock()
	e.connsDone = true
	conns := make([]*exitConn, 0, len(e.conns))
	for c := range e.conns {
		conns = append(conns, c)
	}
	e.conns = nil
	e.connMu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func (e *exit) retire() {
	e.mu.Lock()
	e.retired = true
	closeNow := e.closeReadyLocked()
	e.mu.Unlock()
	// Close active tunnels immediately. A penalized exit is usually already
	// answering 429, and a long-lived CONNECT tunnel would otherwise keep
	// retrying through the exhausted egress while its replacement sits unused.
	e.closeConns()
	if closeNow {
		e.close()
	}
}

func (e *exit) close() {
	e.closeOnce.Do(func() {
		e.mu.Lock()
		e.closed = true
		e.mu.Unlock()
		if e.device != nil {
			e.device.Close()
			<-e.device.Wait()
		}
	})
}

func (e *exit) observe(status int, body []byte) (bool, string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.penalized {
		return false, ""
	}
	// 403 是形态或身份信号, 换出口无益.
	if status == http.StatusForbidden {
		return false, ""
	}
	// A free-tier 429 is scoped to the egress address, not to the request, the
	// key or the session: retrying the same exit repeats it. Replace the exit
	// on the first one, as the instant-rotate deployment does, so the retry
	// draws a fresh outer source and a new public egress.
	if status == http.StatusTooManyRequests {
		return true, "HTTP 429"
	}
	return false, ""
}

func (e *exit) markPenalized() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.penalized {
		return false
	}
	e.penalized = true
	return true
}

func (e *exit) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if e.network == nil {
		return nil, errors.New("WARP network is closed")
	}
	e.mu.Lock()
	retired := e.retired || e.closed
	e.mu.Unlock()
	if retired {
		return nil, errors.New("WARP exit is retired")
	}
	network = strings.ToLower(strings.TrimSpace(network))
	switch network {
	case "tcp":
		network = e.dialNetwork()
	case "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("WARP supports TCP only, got %q", network)
	}
	switch e.stack {
	case StackIPv4:
		if network != "tcp4" {
			return nil, fmt.Errorf("WARP IPv4 stack cannot dial %q", network)
		}
	case StackIPv6:
		if network != "tcp6" {
			return nil, fmt.Errorf("WARP IPv6 stack cannot dial %q", network)
		}
	case StackDual:
		// Both address families are present in the netstack.
	default:
		return nil, fmt.Errorf("unsupported WARP stack %q", e.stack)
	}
	conn, err := e.network.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	tracked := &exitConn{Conn: conn, exit: e}
	if !e.trackConn(tracked) {
		_ = conn.Close()
		return nil, errors.New("WARP exit is retired")
	}
	return tracked, nil
}

func (e *exit) dialNetwork() string {
	switch e.stack {
	case StackIPv4:
		return "tcp4"
	case StackDual:
		if e.egress.Is4() {
			return "tcp4"
		}
		return "tcp6"
	default:
		return "tcp6"
	}
}

func (e *exit) egressKey() string {
	return egressPrefix(e.egress)
}

// egressPrefix 返回 IPv6 /64 或 IPv4 /32 的配额键.
func egressPrefix(addr netip.Addr) string {
	if addr.Is4() {
		return netip.PrefixFrom(addr, 32).Masked().String()
	}
	if !addr.Is6() {
		return ""
	}
	// The free tier treats a Cloudflare /64 as one quota scope: rotating inside
	// the same /64 yields a new /128 but the same exhausted quota. Keying on
	// the /64 keeps every active and cooling exit on a distinct scope, so a
	// replacement is a real rotation rather than a cosmetic address change.
	return netip.PrefixFrom(addr, 64).Masked().String()
}

// sameEgressPrefix 判断两个出口是否落在同一配额段.
func sameEgressPrefix(a, b netip.Addr) bool {
	if !a.IsValid() || !b.IsValid() {
		return false
	}
	return egressPrefix(a) == egressPrefix(b)
}

// idle reports whether no lease currently holds this exit.
func (e *exit) idle() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.refs == 0 && !e.retired && !e.closed
}

// available 表示出口仍可承载流量.
func (e *exit) available() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return !e.retired && !e.closed && !e.penalized
}
